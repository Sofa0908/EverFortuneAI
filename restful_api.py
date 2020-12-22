import re

from flask import Flask, jsonify, request, session
from flask_jwt_extended import JWTManager
from flask_marshmallow import Marshmallow
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc
from werkzeug.security import check_password_hash, generate_password_hash

from config import *
from models import *

app = Flask("EverFortuneAI")
api = Api(app)
app.config.from_object(MyConfig)
db = SQLAlchemy(app)
ma = Marshmallow(app)
jwt = JWTManager(app)

# Register user into the system
# Expected Input: accName (STR), displayName (STR), password (STR), password2 (STR)
@app.route('/register/', methods = ['POST'])
def register():
  if request.json['password'] == request.json['password2']:
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
      db.session.rollback()
      return jsonify({ # Or return redirect(url_for('register'))
        'Status': f'Failed',
        'Message': f'User Already Exists, please try another accName'
      }), 400
  else:
    return jsonify({ # Or return redirect(url_for('register'))
      'Status': f'Failed',
      'Message': f'Please check password again.'
    }), 400

  return jsonify({ # Or return redirect(url_for('login'))
    'Status': f'Success',
    'Message': f'User registered.'
  }), 200

# Logs current user into the system 
# [NOTE: New User log in WILL be able to overwrite current user's session]
# Expected Input: accName (STR), password (STR)
@app.route('/login/', methods = ['POST'])
def login():
  user = UserLogin.query.filter_by(accName=request.json['accName']).first()
  if user:
    if check_password_hash(user.pwHash, request.json['password']):
      session['userID'] = user.userID
      session['accName'] = user.accName
      session['displayName'] = user.displayName
      session['logged_in'] = True
      return jsonify({ # Or return redirect(url_for('home'))
        'Status': f'Success',
        'Message': f'User logged in.'
      }), 200
    else:
      return jsonify({ # Or return redirect(url_for('login'))
        'Status': f'Failed',
        'Message': f'Account or Password incorrect.'
      }), 400

# Logs out current user
@app.route('/logout/')
def logout():
  if 'accName' not in session:
    return jsonify({ # Or return redirect(url_for('login'))
      'Status': f'Failed',
      'Message': f'Not logged in, cannot log out'
    }), 404
  session['logged_in'] = False
  session.pop('accName', None)

  return jsonify({ # Or return redirect(url_for('home'))
    'Status': f'Success',
    'Message': f'User logged out'
  }), 200

#===================================================================================================
# Add Comments to site
# Expected Input: siteID (CHAR(4)), comment (STR)
@app.route('/comment/add/', methods = ['POST'])
def addComment():
  if 'accName' not in session and session['logged_in']:
    return jsonify({ # Or return redirect(url_for('login'))
      'Status': f'Failed',
      'Message': f'Please Login before commenting'
    }), 401
  else:
    new_comment = Comments(
      commDet = request.json['comment'],
      userID = session['userID'],
      siteID = request.json['siteID']
    )
    try:
      db.session.add(new_comment)
      db.session.commit()
    except exc.DBAPIError as e:
      db.session.rollback()
      return jsonify({ # Or return redirect(url_for('register'))
        'Status': f'Failed',
        'Message': e
      }), 400
    return jsonify({ # Or return redirect(url_for('sitePage'))
      'Status': f'Success',
      'Message': f'Comment added'
    }), 200

# Remove Comments that belongs to current user
# Expected Input: commID (INT)
@app.route('/comment/remove/', methods = ['POST'])
def removeComment():
  if 'accName' not in session and session['logged_in']:
    return jsonify({ # Or return redirect(url_for('login'))
      'Status': f'Failed',
      'Message': f'Please Login before removing a comment'
    }), 401
  else:
    trash = Comments.query.filter_by(commID=request.json['commID']).first()
    if trash and trash.userID == session['userID']:
      db.session.delete(trash)
      db.session.commit()
      return jsonify({ # Or return redirect(url_for('sitePage'))
        'Status': f'Success',
        'Message': f'Comment removed'
      }), 200
    else:
      return jsonify({ # Or return redirect(url_for('sitePage'))
        'Status': f'Failed',
        'Message': f'Comment not found for removal or Comment does not belong to current user'
      }), 400

# Update Comment that belongs to current user
# Expected Input: updatedComment (STR), commID (INT)
@app.route('/comment/update/', methods = ['POST'])
def updateComment():
  if 'accName' not in session and session['logged_in']:
    return jsonify({ # Or return redirect(url_for('login'))
      'Status': f'Failed',
      'Message': f'Please Login before updating a comment'
    }), 401
  else:
    cargo = Comments.query.filter_by(commID=request.json['commID']).first()
    if cargo and cargo.userID == session['userID']:
      cargo.commDet = request.json['updatedComment']
      db.session.commit()
      return jsonify({ # Or return redirect(url_for('sitePage'))
        'Status': f'Success',
        'Message': f'Comment updated'
      }), 200
    else:
      return jsonify({ # Or return redirect(url_for('sitePage'))
        'Status': f'Failed',
        'Message': f'Comment not found for update or Comment does not belong to current user'
      }), 400

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
      'Status':f'Failed'
    }), 404
  return jsonify({'Status':f'Success'},output), 200

# Separates Chinese and English Character for filter
def separateCHN(n):
  n_c = ''
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
  try:
    result = db.session.query(SiteStatus) \
            .join(Comments, Comments.siteID == SiteStatus.siteID, isouter=True) \
            .group_by(SiteStatus.siteID) \
            .order_by(db.func.count(Comments.commID).desc()) \
            .paginate(page=page, per_page=ROWS_PER_PAGE)

    site_schema = SiteStatusNestSchema(many=True)
    output = site_schema.dump(result.items)
    
    if area:
      area, area_CHN = separateCHN(area)
    if name:  
      name, name_CHN = separateCHN(name)

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
      'Status':f'Failed'
    }), 404

  return jsonify({'Status':f'Success'},output), 200

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
    }), 404

  return jsonify({'Status':f'Success'},output), 200

if __name__ == '__main__':
  app.run(debug=True)
