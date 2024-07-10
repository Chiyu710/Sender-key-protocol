import pymysql
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519

from cryptographic_material import encode_bytes_pub, encode_bytes_priv


def pre_key_store(id, ik_pub, spk_pub, spk_sign, signature, opks):
    connection = pymysql.connect(host='localhost',
                                 user='root',
                                 port=3307,
                                 password='root',
                                 db='sender_key'
                                 )

    ik_pub = encode_bytes_pub(ik_pub)
    spk_pub = encode_bytes_pub(spk_pub)
    spk_sign = encode_bytes_pub(spk_sign)

    try:
        with connection.cursor() as cursor:
            # Insert data into prekey table
            sql_prekey = "INSERT INTO prekey (id, ik, spk, spk_sign, signature) VALUES (%s, %s, %s, %s, %s)"
            cursor.execute(sql_prekey, (id, ik_pub, spk_pub, spk_sign, signature))

            sql_opks = "INSERT INTO opks (opk, user_id, opk_index) VALUES (%s, %s, %s)"
            for index, (priv, pub) in enumerate(opks):
                pub = encode_bytes_pub(pub)
                cursor.execute(sql_opks, (pub, id, index))
        connection.commit()
    except Exception as e:
        connection.rollback()
        print(f"An error occurred: {e}")


def get_prekey_data(id):
    connection = pymysql.connect(host='localhost',
                                 user='root',
                                 port=3307,
                                 password='root',
                                 db='sender_key'
                                 )
    try:
        with connection.cursor() as cursor:
            # Retrieve data from prekey table
            sql_prekey = "SELECT ik, spk, spk_sign, signature FROM prekey WHERE id = %s"
            cursor.execute(sql_prekey, id)
            prekey_data = cursor.fetchone()
            if not prekey_data:
                return None
            ik_pub, spk_pub, spk_sign, signature = prekey_data

            # Retrieve associated opk data
            sql_opks = "SELECT opk, opk_index FROM opks WHERE user_id = %s LIMIT 1"
            cursor.execute(sql_opks, id)
            opk_data = cursor.fetchone()
            if not opk_data:
                return None
            opk, opk_index = opk_data

            # there should be a delete code
            # print(opk)
            # Convert keys from byte type to key type
            ik_pub = x25519.X25519PublicKey.from_public_bytes(ik_pub)
            spk_pub = x25519.X25519PublicKey.from_public_bytes(spk_pub)
            opk = x25519.X25519PublicKey.from_public_bytes(opk)
            spk_sign = ed25519.Ed25519PublicKey.from_public_bytes(spk_sign)
            return ik_pub, spk_pub, spk_sign, signature, opk, opk_index


    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def store_state(state):
    connection = pymysql.connect(host='localhost',
                                 user='root',
                                 port=3307,
                                 password='root',
                                 db='sender_key')

    try:
        with connection.cursor() as cursor:
            # Insert data into user table
            sql_user = """
            INSERT INTO user (id, ik, ik_pub, spk, spk_pub, prekey_signature)
            VALUES (%s, %s, %s, %s, %s, %s)
            """
            cursor.execute(sql_user, (state.id,
                                      encode_bytes_priv(state.ik), encode_bytes_pub(state.ik_pub),
                                      encode_bytes_priv(state.spk), encode_bytes_pub(state.spk_pub),
                                      state.prekey_signature))

        connection.commit()
    except Exception as e:
        connection.rollback()
        print(f"An error occurred: {e}")


def retrieve_state(id):
    connection = pymysql.connect(host='localhost',
                                 user='root',
                                 port=3307,
                                 password='root',
                                 db='sender_key')
    try:
        with connection.cursor() as cursor:
            # Retrieve data from user table
            sql_user = """
            SELECT ik, ik_pub, spk, spk_pub, prekey_signature
            FROM user WHERE id = %s
            """
            cursor.execute(sql_user, id)
            user_data = cursor.fetchone()
            if not user_data:
                return None

            (ik, ik_pub, spk, spk_pub, prekey_signature) = user_data

            # Convert keys from byte type to key type

            ik = x25519.X25519PrivateKey.from_private_bytes(ik)
            ik_pub = x25519.X25519PublicKey.from_public_bytes(ik_pub)
            spk = x25519.X25519PrivateKey.from_private_bytes(spk)
            spk_pub = x25519.X25519PublicKey.from_public_bytes(spk_pub)
            prekey_signature = prekey_signature

            return ik, ik_pub, spk, spk_pub, prekey_signature

    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def search_id(id):
    connection = pymysql.connect(host='localhost',
                                 user='root',
                                 port=3307,
                                 password='root',
                                 db='sender_key')
    try:
        with connection.cursor() as cursor:
            # Insert data into user table
            sql_user = """
                SELECT  id FROM prekey WHERE id  = %s
                """
            cursor.execute(sql_user, id)
            user_id = cursor.fetchone()
        if user_id != None:
            return True
        else:
            return False
    except Exception as e:
        connection.rollback()
        print(f"An error occurred: {e}")
