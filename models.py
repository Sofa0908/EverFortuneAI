from restful_api import db, ma
from passlib.hash import pbkdf2_sha256 as sha256

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
  
  siteDataID = db.Column(db.String(4), primary_key=True)
  totalSlot = db.Column(db.Integer)
  Lat = db.Column(db.Float)
  Lng = db.Column(db.Float)
  siteID = db.Column(db.String(4), db.ForeignKey('sys.Site_Status.siteID'))

  def __init__(self, siteDataID, totalSlot, Lat, Lng, siteID):
    self.siteDataID = siteDataID
    self.totalSlot = totalSlot
    self.Lat = Lat
    self.Lng = Lng
    self.siteID = siteID

class SiteInfo(db.Model):
  __tablename__ = 'Site_Info'
  __table_args__ = {"schema": "sys"}
  
  siteInfoID = db.Column(db.String(4), primary_key=True)
  siteName = db.Column(db.NVARCHAR(60))
  siteArea = db.Column(db.NVARCHAR(60))
  addr = db.Column(db.NVARCHAR(120))
  siteID = db.Column(db.String(4), db.ForeignKey('sys.Site_Status.siteID'))

  def __init__(self, siteInfoID, siteName, siteArea, addr, siteID):
    self.siteInfoID = siteInfoID
    self.siteName = siteName
    self.siteArea = siteArea
    self.addr = addr
    self.siteID = siteID

class SiteInfoEng(db.Model):
  __tablename__ = 'Site_InfoEng'
  __table_args__ = {"schema": "sys"}
  
  siteInfoENID = db.Column(db.String(4), primary_key=True)
  siteNameEN = db.Column(db.Text)
  siteAreaEN = db.Column(db.Text)
  addrEN = db.Column(db.Text)
  siteID = db.Column(db.String(4), db.ForeignKey('sys.Site_Status.siteID'))

  def __init__(self, siteInfoENID, siteNameEN, siteAreaEN, addrEN, siteID):
    self.siteInfoENID = siteInfoENID
    self.siteNameEN = siteNameEN
    self.siteAreaEN = siteAreaEN
    self.addrEN = addrEN
    self.siteID = siteID

class SiteDataSchema(ma.Schema):
  class Meta:
    model = SiteData
    fields = ('totalSlot', 'Lat', 'Lng')
  
class SiteInfoSchema(ma.Schema):
  class Meta:
    model = SiteInfo
    fields = ('siteName', 'siteArea', 'addr')

class SiteInfoEngSchema(ma.Schema):
  class Meta:
    model = SiteInfoEng
    fields = ('siteNameEN', 'siteAreaEN', 'addrEN')

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

class RevokedSchema(ma.Schema):
  class Meta:
    fields = ('id','jti')

# User Model class
class UserLogin(db.Model):
  __tablename__ = 'User_Login'
  __table_args__ = {"schema": "sys"}

  userID = db.Column(db.Integer, primary_key=True)
  accName = db.Column(db.String(120), unique=True)
  displayName = db.Column(db.String(30))
  pwHash = db.Column(db.String(120))

  def __init__(self, accName, displayName, pwHash):
    self.accName = accName
    self.displayName = displayName
    self.pwHash = pwHash

  # save user to db
  def save_to_db(self):
    db.session.add(self)
    db.session.commit()
  
  # find user by name
  @classmethod
  def find_by_accName(cls, accName):
    return cls.query.filter_by(accName=accName).first()

  # generate hash from pw
  @staticmethod
  def generate_hash(pwHash):
    return sha256.hash(pwHash)
  
  # verify hash from pw
  @staticmethod
  def verify_hash(pwHash, hash_):
    return sha256.verify(pwHash, hash_)

# Revoked Token Class
class RevokedTokenModel(db.Model):
  __tablename__ = 'revoked_tokens'
  id = db.Column(db.Integer, primary_key=True)
  # jti stans for JWT ID
  jti = db.Column(db.String(120))

  # Save token to db
  def add(self):
    db.session.add(self)
    db.session.commit()

  # check if token is black listed
  @classmethod
  def is_jti_blacklisted(cls, jti):
    result = cls.query.filter_by(jti=jti).first
    schema = RevokedSchema()
    out = schema.dump(result)

    if len(out) < 1:
      return False
    else:
      return True