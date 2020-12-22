import urllib.request
import json
import pymysql
import sys

def reader():
  with urllib.request.urlopen("https://tcgbusfs.blob.core.windows.net/blobyoubike/YouBikeTP.json") as url:
    pkg = json.loads(url.read())
  
  try:
    if pkg['retCode'] == 1:
      data = pkg['retVal']
    else:
      return False
  except KeyError as e:
    print('KeyError: ', e)
    return False

  return data

def first_parser(data, cur):
  for site in data:
    # Site Status
    ID = data[site]['sno']
    Aval = int(data[site]['sbi'])
    ModTime = data[site]['mday']
    Active = int(data[site]['act'])
    RemainSpace = int(data[site]['bemp'])
    
    sql = """
    INSERT INTO sys.Site_Status (SiteID, AvalBike, ModTime, Act, RemainSpace) VALUES (%s, %s, %s, %s, %s)
    """
    try:
      cur.execute(sql, (ID, Aval, ModTime, Active, RemainSpace))
    except (pymysql.Error, pymysql.Warning) as e:
      print(e)
      return False
    
    # Site Data
    Total = int(data[site]['tot'])
    Lat = float(data[site]['lat'])
    Lng = float(data[site]['lng'])
    
    sql = """
    INSERT INTO sys.Site_Data (SiteDataID, TotalSlot, Lat, Lng, SiteID) VALUES (%s, %s, %s, %s, %s)
    """
    try:
      cur.execute(sql, (ID, Total, Lat, Lng, ID))
    except (pymysql.Error, pymysql.Warning) as e:
      print(e)
      return False
    
    # Site Info
    Name = data[site]['sna']
    Area = data[site]['sarea']
    Addr = data[site]['ar']
    
    sql = """
    INSERT INTO sys.Site_Info (SiteInfoID, SiteName, SiteArea, Addr, SiteID) VALUES (%s, N%s, N%s, N%s, %s)
    """
    try:
      cur.execute(sql, (ID, Name, Area, Addr, ID))
    except (pymysql.Error, pymysql.Warning) as e:
      print(e)
      return False

    # Site Info Eng
    NameEN = data[site]['snaen']
    AreaEN = data[site]['sareaen']
    AddrEN = data[site]['aren']

    sql = """
    INSERT INTO sys.Site_InfoEng (SiteInfoENID, SiteNameEN, SiteAreaEN, AddrEN, SiteID) VALUES (%s, %s, %s, %s, %s)
    """
    try:
      cur.execute(sql, (ID, NameEN, AreaEN, AddrEN, ID))
    except (pymysql.Error, pymysql.Warning) as e:
      print(e)
      return False
  
  return True

def updater(data, cur):
  for site in data:  
    Aval = int(data[site]['sbi'])
    ModTime = data[site]['mday']
    Active = int(data[site]['act'])
    RemainSpace = int(data[site]['bemp'])
    ID = data[site]['sno']
    
    sql = """
    UPDATE sys.Site_Status 
    SET AvalBike = %s, ModTime = %s, Act = %s, RemainSpace = %s
    WHERE SiteID = %s
    """
    try:
      cur.execute(sql, (Aval, ModTime, Active, RemainSpace, ID))
    except (pymysql.Error, pymysql.Warning) as e:
      print(e)
      return False
  return True

if __name__ == "__main__":
  conn = pymysql.connect(host='localhost', 
                         user='root', 
                         unix_socket="/tmp/mysql.sock",
                         passwd='Nocompl3x!', 
                         port=3306,
                         db='mysql')
  cur = conn.cursor()
  
  data = reader()
  if not data:
    print('Failed to retrieve JSON from url')
    cur.close()
    conn.close()
    sys.exit()
  else:
    sql = "SELECT SiteID FROM sys.Site_Status LIMIT 404"
    try:
      cur.execute(sql)
    except (pymysql.Error, pymysql.Warning) as e:
      print(e)
      cur.close()
      conn.close()
      sys.exit()
    if len(cur.fetchall()) < 1:
      result = first_parser(data, cur)
      print('add new')
    else:
      result = updater(data, cur)
      print('update')

  if result:
    conn.commit()
    print('committed')

  cur.close()
  conn.close()