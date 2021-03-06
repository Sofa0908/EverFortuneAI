import re

from flask import Flask, jsonify, request, session
from flask_jwt_extended import (
  JWTManager,
  create_access_token,
  create_refresh_token,
  jwt_required,
  jwt_refresh_token_required,
  get_jwt_identity,
  get_raw_jwt
)
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

# Check if Token is blacklisted
@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
  jti = decrypted_token['jti']
  return RevokedTokenModel.is_jti_blacklisted(jti)

# JWT Registration
# Expected Input: accName (STR) | displayName (STR) | password (STR)
@app.route('/registration/', methods = ['POST'])
def registration():
  accName = request.json['accName']

  if UserLogin.find_by_accName(accName):
    return {'message': f'user name {accName} already exists'}, 400
  
  new_user = UserLogin(
    accName = accName,
    displayName = request.json['displayName'],
    pwHash = UserLogin.generate_hash(request.json['password'])
  )

  try:
    # when save user to db, generate access and refresh token
    new_user.save_to_db()
    access_token = create_access_token(identity=accName)
    refresh_token = create_refresh_token(identity=accName)
    return {
      'Message': f'User {accName} created',
      'access_token': access_token,
      'refresh_token': refresh_token
    }, 200
  except:
    return {'Message': f'[REG] Something went wrong'}, 500

# JWT login
# Expected Input: accName (STR) | password (STR)
@app.route('/login/', methods = ['POST'])
def login():
  accName = request.json['accName']

  # get user data by accName
  cur_user = UserLogin.find_by_accName(accName)

  if not cur_user:
    return {'Message': f'User {accName} does not exist'}, 400

  if UserLogin.verify_hash(request.json['password'], cur_user.pwHash):
    access_token = create_access_token(identity=accName)
    refresh_token = create_refresh_token(identity=accName)
    session['userID'] = cur_user.userID
    return {
      'message': f'Logged in as {accName}',
      'access_token': access_token,
      'refresh_token': refresh_token
      }, 200
  else:
    return {'message': f'Wrong credentials'}, 401

# JWT Logout access
@app.route('/logout/access/', methods = ['POST'])
@jwt_required
def logoutAccess():
  jti = get_raw_jwt()['jti']
  try:
    #revoking access token
    revoked_token = RevokedTokenModel(jti=jti)
    revoked_token.add()
    return {'Message':f'Access token revoked'}, 200
  except:
    return {'Message': f'[LOGO/A] Something went wrong'}, 500

# JWT Logout refresh
@app.route('/logout/refresh/', methods = ['POST'])
@jwt_refresh_token_required
def logoutRefresh():
  jti = get_raw_jwt()['jti']
  try:
    revoked_token = RevokedTokenModel(jti=jti)
    revoked_token.add()
    return {'Message': f'Refresh token revoked'}, 200
  except:
    return {'Message': f'[LOGO/R] Something went wrong'}, 500

# JWT Token refresher
@app.route('/token/refresh/', methods = ['POST'])
@jwt_refresh_token_required
def tokenRefresh():
  cur_user = get_jwt_identity()
  access_token = create_access_token(identity=cur_user)
  return {'access_token': access_token}, 200

#===================================================================================================
# Add Comments to site
# Expected Input: siteID (CHAR(4)) | comment (STR)
@app.route('/comment/add/', methods = ['POST'])
@jwt_required
def addComment():
  if 'accName' not in session:
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
    except exc.IntegrityError as e:
      db.session.rollback()
      return jsonify({ # Or return redirect(url_for('register'))
        'Status': f'Failed',
        'Error': str(e)
      }), 400
    return jsonify({ # Or return redirect(url_for('sitePage'))
      'Status': f'Success',
      'Message': f'Comment added'
    }), 200

# Remove Comments that belongs to current user
# Expected Input: commID (INT)
@app.route('/comment/remove/', methods = ['POST'])
def removeComment():
  if 'accName' not in session:
    return jsonify({ # Or return redirect(url_for('login'))
      'Status': f'Failed',
      'Message': f'Please Login before removing a comment'
    }), 401
  else:
    trash = Comments.query.filter_by(commID=int(request.json['commID'])).first()
    
    if trash and int(trash.userID) == int(session['userID']):
      try:
        current_session = db.session.object_session(trash)
        current_session.delete(trash)
        current_session.commit()
      except exc.InvalidRequestError as e:
        db.session.rollback()
        return jsonify({ # Or return redirect(url_for('register'))
          'Status': f'Failed',
          'Message': str(e)
        }), 400
      
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
# Expected Input: updatedComment (STR) | commID (INT)
@app.route('/comment/update/', methods = ['POST'])
def updateComment():
  if 'accName' not in session:
    return jsonify({ # Or return redirect(url_for('login'))
      'Status': f'Failed',
      'Message': f'Please Login before updating a comment'
    }), 401
  else:
    cargo = Comments.query.filter_by(commID=int(request.json['commID'])).first()
    if cargo and cargo.userID == session['userID']:
      try:
        current_session = db.session.object_session(cargo)
        cargo.commDet = request.json['updatedComment']
        current_session.commit()
      except exc.InvalidRequestError as e:
        db.session.rollback()
        return jsonify({ # Or return redirect(url_for('register'))
          'Status': f'Failed',
          'Error': str(e)
        }), 400
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
@app.route('/site-by-comment/', methods = ['GET'])
@jwt_required
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
  except exc.InvalidRequestError as e:
    return jsonify({
      'Status':f'Failed',
      'Error': str(e)
    }), 400
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
@app.route('/site-filter/', methods = ['GET'])
@jwt_required
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
    else:
      area_CHN = ''
    if name:  
      name, name_CHN = separateCHN(name)
    else:
      name_CHN = ''

    for item in list(output):
      if (len(name_CHN) > 0 and name_CHN not in item['info'][0]['siteName'].lower()) or \
        (len(area_CHN)> 0 and area_CHN not in item['info'][0]['siteArea'].lower()):
        output.remove(item)
      if ((len(name) > 0 and name not in item['infoEng'][0]['siteNameEN'].lower()) or \
        (len(area)> 0 and area not in item['infoEng'][0]['siteAreaEN'].lower())) and \
        item in output:
        output.remove(item)
  except exc.InvalidRequestError as e:
    return jsonify({
      'Status':f'Failed',
      'Error': str(e)
    }), 400

  return jsonify({'Status':f'Success'},output), 200

# Return sites with no bike
@app.route('/site-no-bike/', methods = ['GET'])
@jwt_required
def getSiteWithNoBike():
  try:
    sites = SiteStatus.query.filter_by(avalBike=0).all()
    site_schema = SiteStatusSchema(many=True)
    output = site_schema.dump(sites)
  except exc.InvalidRequestError as e:
    return jsonify({
      'Status':f'Failed',
      'Error': str(e)
    }), 400

  return jsonify({'Status':f'Success'},output), 200

if __name__ == '__main__':
  app.run(debug=True)
