#!/bin/usr/env python

import sqlite3

db = sqlite3.connect('analysis.db', detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)
db.row_factory = sqlite3.Row
cursor = db.cursor()
cursor.execute('''SELECT filename, extension, status, timestampdb FROM files''')
for row in cursor:
    # row['name'] returns the name column in the query, row['email'] returns email column.
    print('{0} : {1}, {2}, {3}'.format(row['filename'], row['extension'], row['status'], row['timestampdb']))
    
#cursor.execute('select timestampdb as "timestampdb [timestamp]"')
#row = cursor.fetchone()
#print row
db.close()

