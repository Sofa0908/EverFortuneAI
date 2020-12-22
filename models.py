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