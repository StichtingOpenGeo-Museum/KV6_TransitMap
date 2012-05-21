import sys
import monetdb.sql
from secret import sql_username, sql_password, sql_hostname, sql_port, sql_database

def querystops():
    sys.stderr.write('Query all pointplace locations... ')
    sql = """SELECT u.dataownercode||'|'||u.userstopcode, u.name, u.town, p.locationx_ew, p.locationy_ns
             FROM usrstop AS u, point AS p
             WHERE u.dataownercode = p.dataownercode AND u.userstopcode = p.pointcode AND p.pointtype = 'SP';"""
    connection = monetdb.sql.connect(username=sql_username, password=sql_password,
                                     hostname=sql_hostname, port=sql_port, database=sql_database, autocommit=True)

    cursor = connection.cursor()
    cursor.execute(sql)

    stops = {}
    for stop_id, name, town, locationx_ew, locationy_ns in cursor.fetchall():
        stops[stop_id] = {'description': name, 'locality': town, 'rd_x': locationx_ew, 'rd_y': locationy_ns}

    sys.stderr.write(' %d cached\n' % len(stops))
    return stops
