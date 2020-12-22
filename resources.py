import pdb

from flask_restful import Resource, reqparse
from models import UserLogin, RevokedTokenModel
from flask_jwt_extended import (
  create_access_token,
  create_refresh_token,
  jwt_required,
  jwt_refresh_token_required,
  get_jwt_identity,
  get_raw_jwt
)

# says to provide uniformed access
parser = reqparse.RequestParser()
parser.add_argument('accName', help='accName cannot be blank', required=True)
parser.add_argument('displayName', help='displayName cannot be blank', required=True)
parser.add_argument('pwHash', help='pwHash cannot be blank', required=True)

class UserRegistration(Resource):
  # user registration func
  def post(self):
    data = parser.parse_args()
    
    accName = data['accName']

    if UserLogin.find_by_accName(accName):
      return {'message': f'user name {accName} already exists'}
    
    new_user = UserLogin(
      accName = accName,
      displayName = data['displayName'],
      pwHash = UserLogin.generate_hash(data['pwHash'])
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
      }
    except:
      return {'Message': 'What could go wrong will go wrong I guess?'}, 500

class Login(Resource):
  # User Login func
  def post(self):
    data = parser.parse_args()
    accName = data['accName']

    # get user data by accName
    cur_user = UserLogin.find_by_accName(accName)

    if not cur_user:
      return {'Message': f'User {accName} does not exist'}

    if UserLogin.verify_hash(data['pwHash'], cur_user.pwHash):
      access_token = create_access_token(identity=accName)
      refresh_token = create_refresh_token(identity=accName)

      return {
        'message': f'Logged in as {accName}',
        'access_token': access_token,
        'refresh_token': refresh_token
        }
    else:
      return {'message': "Wrong credentials"}

class UserLogoutAccess(Resource):
  # User Logout func
  @jwt_required
  def post(self):
    jti = get_raw_jwt()['jti']

    try:
      #revoking access token
      revoked_token = RevokedTokenModel(jti=jti)
      revoked_token.add()
      return{'Message':f'Access token revoked'}
    except:
      return {'Message': 'What could go wrong will go wrong I guess?'}, 500

class UserLogoutRefresh(Resource):
  # User Logout refresh func, it revokes the refresh token when user logs out
  @jwt_refresh_token_required
  def post(self):
    jti = get_raw_jwt()['jti']

    try:
      revoked_token = RevokedTokenModel(jti=jti)
      revoked_token.add()
      pdb.set_trace()
      return {'Message': 'Refresh token revoked'}
    except:
      return {'Message': 'What could go wrong will go wrong I guess?'}, 500

class TokenRefresh(Resource):
  # Refreshes the token for user through refresh token
  @jwt_refresh_token_required
  def post(self):
    # Generate new access token
    cur_user = get_jwt_identity()
    access_token = create_access_token(identity=cur_user)
    return {'access_token': access_token}

class TestSecretAccess(Resource):
  # Test func to see if jwt is working
  @jwt_required
  def get(self):
    return {'answer': 'Okay, it is working, jwt let\'s goooo'}
  