from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Api
from werkzeug.security import generate_password_hash, check_password_hash
from flask_marshmallow import Marshmallow
from sqlalchemy import exc
import re


app = Flask(__name__)
api = Api(app)
app.config['SECRET_KEY'] = 't;6ru8 54s/6'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Nocompl3x!@localhost/sys'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
ma = Marshmallow(app)

#===================================================================================================
# Marshmallow model declarations, for better transition b/w sqlalchemy to json
class Comments(db.Model):
  __tablename__ = 'Comments'
  __table_args__ = {"schema": "sys"}

  commID = db.Column(db.Integer, primary_key=True)
  commDet = db.Column(db.Text)
  userID = db.Column(db.Integer, db.ForeignKey('sys.User_Login.userID'))
  siteID = db.Column(db.String(4), db.ForeignKey('sys.Site_Status.siteID'))

  def __init__(self, commDet, userID, siteID):
    self.commDet = commDet
    self.userID = userID
    self.siteID = siteID

class UserLogin(db.Model):
  __tablename__ = 'User_Login'
  __table_args__ = {"schema": "sys"}

  userID = db.Column(db.Integer, primary_key=True)
  accName = db.Column(db.String(30), unique=True)
  displayName = db.Column(db.String(30))
  pwHash = db.Column(db.String(40))

  def __init__(self, accName, displayName, pwHash):
    self.accName = accName
    self.displayName = displayName
    self.pwHash = pwHash

class SiteStatus(db.Model):
  __tablename__ = 'Site_Status'
  __table_args__ = {"schema": "sys"}
  
  siteID = db.Column(db.String(4), primary_key=True)
  avalBike = db.Column(db.Integer)
  modTime = db.Column(db.String(14))
  act = db.Column(db.Boolean)
  remainSpace = db.Column(db.Integer)
  data = db.relationship("SiteData", backref="Site_Status")
  info = db.relationship("SiteInfo", backref="Site_Status")
  infoEng = db.relationship("SiteInfoEng", backref="Site_Status")

  def __init__(self, siteID, avalBike, modTime, act, remainSpace):
    self.siteID = siteID
    self.avalBike = avalBike
    self.modTime = modTime
    self.act = act
    self.remainSpace = remainSpace

class SiteData(db.Model):
  __tablename__ = 'Site_Data'
  __table_args__ = {"schema": "sys"}
  
  siteID = db.Column(db.String(4), db.ForeignKey('sys.Site_Status.siteID'), primary_key=True)
  totalSlot = db.Column(db.Integer)
  Lat = db.Column(db.Float)
  Lng = db.Column(db.Float)

  def __init__(self, siteID, totalSlot, Lat, Lng):
    self.siteID = siteID
    self.totalSlot = totalSlot
    self.Lat = Lat
    self.Lng = Lng

class SiteInfo(db.Model):
  __tablename__ = 'Site_Info'
  __table_args__ = {"schema": "sys"}
  
  siteID = db.Column(db.String(4), db.ForeignKey('sys.Site_Status.siteID'), primary_key=True)
  siteName = db.Column(db.NVARCHAR(60))
  siteArea = db.Column(db.NVARCHAR(60))
  addr = db.Column(db.NVARCHAR(120))

  def __init__(self, siteID, siteName, siteArea, addr):
    self.siteID = siteID
    self.siteName = siteName
    self.siteArea = siteArea
    self.addr = addr

class SiteInfoEng(db.Model):
  __tablename__ = 'Site_InfoEng'
  __table_args__ = {"schema": "sys"}
  
  siteID = db.Column(db.String(4), db.ForeignKey('sys.Site_Status.siteID'), primary_key=True)
  siteNameEN = db.Column(db.Text)
  siteAreaEN = db.Column(db.Text)
  addrEN = db.Column(db.Text)

  def __init__(self, siteID, siteNameEN, siteAreaEN, addrEN):
    self.siteID = siteID
    self.siteNameEN = siteNameEN
    self.siteAreaEN = siteAreaEN
    self.addrEN = addrEN

class SiteDataSchema(ma.Schema):
  class Meta:
    model = SiteData
    fields = ('siteID', 'totalSlot', 'Lat', 'Lng')
  
class SiteInfoSchema(ma.Schema):
  class Meta:
    model = SiteInfo
    fields = ('siteID', 'siteName', 'siteArea', 'addr')

class SiteInfoEngSchema(ma.Schema):
  class Meta:
    model = SiteInfoEng
    fields = ('siteID', 'siteNameEN', 'siteAreaEN', 'addrEN')

class SiteStatusSchema(ma.Schema):
  class Meta:  
    model = SiteStatus
    fields = ('siteID', 'avalBike', 'modTime', 'act', 'remainSpace')

class SiteStatusNestSchema(ma.Schema):
  class Meta:
    model = SiteStatus
    fields = ('siteID', 'avalBike', 'modTime', 'act', 'remainSpace', 'data', 'info', 'infoEng')
  data = ma.Nested(SiteDataSchema, many=True)
  info = ma.Nested(SiteInfoSchema, many=True)
  infoEng = ma.Nested(SiteInfoEngSchema, many=True)

#===================================================================================================
# Register user into the system
# Expected Input: accName (STR), displayName (STR), password (STR), password2 (STR)
@app.route('/register/', methods = ['POST'])
def register():
  if request.method == 'POST' and request.json['password'] == request.json['password2']:
    hashed_pw = generate_password_hash(request.json['password'], method='sha256')
    new_user = UserLogin(
      accName = request.json['accName'],
      displayName = request.json['displayName'],
      pwHash = hashed_pw
    )
    try:
      db.session.add(new_user)
      db.session.commit()
    except exc.IntegrityError as e:
      return jsonify({ # Or return redirect(url_for('register'))
        'Status': f'Failed',
        'Message': f'User Already Exists, please try another accName'
      })
  else:
    return jsonify({ # Or return redirect(url_for('register'))
      'Status': f'Failed',
      'Message': f'Please check password again.'
    })

  return jsonify({ # Or return redirect(url_for('login'))
    'Status': f'Success',
    'Message': f'User registered.'
  })

# Logs current user into the system [NOTE: New User log in WILL be able to overwrite current user's session]
# Expected Input: accName (STR), password (STR)
@app.route('/login/', methods = ['POST'])
def login():
  if request.method == 'POST':
    user = UserLogin.query.filter_by(accName=request.json['accName']).first()
    if user:
      if check_password_hash(user.pwHash, request.json['password']):
        session['userID'] = user.userID
        session['accName'] = user.accName
        session['displayName'] = user.displayName
        
        return jsonify({ # Or return redirect(url_for('home'))
          'Status': f'Success',
          'Message': f'User logged in.'
        })
      else:
        return jsonify({ # Or return redirect(url_for('login'))
          'Status': f'Failed',
          'Message': f'Account or Password incorrect.'
        })

# Logs out current user
@app.route('/logout/')
def logout():
  if 'accName' not in session:
    return jsonify({ # Or return redirect(url_for('login'))
      'Status': f'Failed',
      'Message': f'Not logged in, cannot log out'
    })

  session.pop('accName', None)

  return jsonify({ # Or return redirect(url_for('home'))
    'Status': f'Success',
    'Message': f'User logged out'
  })

#===================================================================================================
# Add Comments to site
# Expected Input: siteID (CHAR(4)), comment (STR)
@app.route('/comment/add/', methods = ['POST'])
def addComment():
  if 'accName' not in session:
    return jsonify({ # Or return redirect(url_for('login'))
      'Status': f'Failed',
      'Message': f'Please Login before commenting'
    })
  else:
    new_comment = Comments(
      commDet = request.json['comment'],
      userID = session['userID'],
      siteID = request.json['siteID']
    )
    db.session.add(new_comment)
    db.session.commit()
    return jsonify({ # Or return redirect(url_for('sitePage'))
      'Status': f'Success',
      'Message': f'Comment added'
    })

# Remove Comments that belongs to current user
# Expected Input: commID (INT)
@app.route('/comment/remove/', methods = ['POST'])
def removeComment():
  if 'accName' not in session:
    return jsonify({ # Or return redirect(url_for('login'))
      'Status': f'Failed',
      'Message': f'Please Login before removing a comment'
    })
  else:
    trash = Comments.query.filter_by(commID=request.json['commID']).first()
    if trash and trash.userID == session['userID']:
      db.session.delete(trash)
      db.session.commit()
      return jsonify({ # Or return redirect(url_for('sitePage'))
        'Status': f'Success',
        'Message': f'Comment removed'
      })
    else:
      return jsonify({ # Or return redirect(url_for('sitePage'))
        'Status': f'Failed',
        'Message': f'Comment not found for removal or Comment does not belong to current user'
      })

# Update Comment that belongs to current user
# Expected Input: updatedComment (STR), commID (INT)
@app.route('/comment/update/', methods = ['POST'])
def updateComment():
  if 'accName' not in session:
    return jsonify({ # Or return redirect(url_for('login'))
      'Status': f'Failed',
      'Message': f'Please Login before updating a comment'
    })
  else:
    cargo = Comments.query.filter_by(commID=request.json['commID']).first()
    if cargo and cargo.userID == session['userID']:
      cargo.commDet = request.json['updatedComment']
      db.session.commit()
      return jsonify({ # Or return redirect(url_for('sitePage'))
        'Status': f'Success',
        'Message': f'Comment updated'
      })
    else:
      return jsonify({ # Or return redirect(url_for('sitePage'))
        'Status': f'Failed',
        'Message': f'Comment not found for update or Comment does not belong to current user'
      })

#===================================================================================================
# Sort site by comment count
@app.route('/siteByComment/', methods = ['GET'])
def sortSite(page=1):
  page = request.args.get('page', 1, type=int)
  ROWS_PER_PAGE = 100
  try:
    result = db.session.query(SiteStatus) \
            .join(Comments, Comments.siteID == SiteStatus.siteID, isouter=True) \
            .group_by(SiteStatus.siteID) \
            .order_by(db.func.count(Comments.commID).desc()) \
            .paginate(page=page, per_page=ROWS_PER_PAGE)

    site_schema = SiteStatusNestSchema(many=True)
    output = site_schema.dump(result.items)
  except exc.DBAPIError as e:
    return jsonify({
      'Status':f'Failed',
      'ErrorMessage':e
    })
  return jsonify({'Status':f'Success'},output)

# Separates Chinese and English Character for filter
def separateCHN(n, n_c):
  for i in re.findall(r'[\u4e00-\u9fff]+', n):
    n = n.replace(i, '')
    n_c+=i
  return n.strip(' ').lower(), n_c.strip(' ').lower()

# Sort site by comment count with area/name filters
# Expected Input:  page (INT) | area (STR) | name (STR)
@app.route('/siteWithSearch/', methods = ['GET'])
def sortSiteWithSearch(page=1):
  page = request.args.get('page', 1, type=int)
  area = request.args.get('area', '', type=str)
  name = request.args.get('name', '', type=str)
  ROWS_PER_PAGE = 100
  name_CHN = ''
  area_CHN = ''
  try:
    result = db.session.query(SiteStatus) \
            .join(Comments, Comments.siteID == SiteStatus.siteID, isouter=True) \
            .group_by(SiteStatus.siteID) \
            .order_by(db.func.count(Comments.commID).desc()) \
            .paginate(page=page, per_page=ROWS_PER_PAGE)

    site_schema = SiteStatusNestSchema(many=True)
    output = site_schema.dump(result.items)
    
    if area:
      area, area_CHN = separateCHN(area, area_CHN)
    if name:  
      name, name_CHN = separateCHN(name, name_CHN)

    for item in list(output):
      if (len(name_CHN) > 0 and name_CHN not in item['info'][0]['siteName'].lower()) or \
        (len(area_CHN)> 0 and area_CHN not in item['info'][0]['siteArea'].lower()):
        output.remove(item)
      if ((len(name) > 0 and name not in item['infoEng'][0]['siteNameEN'].lower()) or \
        (len(area)> 0 and area not in item['infoEng'][0]['siteAreaEN'].lower())) and \
        item in output:
        output.remove(item)
  except exc.DBAPIError as e:
    return jsonify({
      'Status':f'Failed',
      'ErrorMessage':e
    })

  return jsonify({'Status':f'Success'},output)

# Return sites with no bike
@app.route('/siteWithNoBike/', methods = ['GET'])
def getSiteWithNoBike():
  try:
    sites = SiteStatus.query.filter_by(avalBike=0).all()
    site_schema = SiteStatusSchema(many=True)
    output = site_schema.dump(sites)
  except exc.DBAPIError as e:
    return jsonify({
      'Status':f'Failed',
      'ErrorMessage':e
    })

  return jsonify({'Status':f'Success'},output)

if __name__ == '__main__':
  app.run(debug=True)