import sqlite3

db = sqlite3.connect("hashes.sqlite")
db.execute("CREATE TABLE IF NOT EXISTS hashes (object TEXT, hash TEXT)")

# TODO: Delete line below once database is confirmed to be working properly
db.execute("INSERT INTO hashes (object, hash) VALUES ('object11089', '7b844a00802d3ec492c11425b72d008f')")
cursor = db.cursor()
cursor.execute("SELECT * FROM hashes")
for row in cursor:
    print(row)

cursor.close()
db.close()
