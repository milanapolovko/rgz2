import os
from os import path
import re
from flask import Flask, render_template,request, session, current_app
import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.security import check_password_hash, generate_password_hash
import sqlite3

app=Flask(__name__)

app.config['SECRET_KEY']= os.environ.get('SECRET_KEY','секретно-секретный секрет')
app.config['DB_TYPE']= os.getenv('DB_TYPE','postgres')

def db_connect():
    if current_app.config['DB_TYPE']=='postgres':
        conn=psycopg2.connect(
            host='127.0.0.1',
            database='milana_polovko',
            user='postgres',
            password='123'
        )
        cur=conn.cursor(cursor_factory=RealDictCursor)
    else:
        dir_path=path.dirname(path.realpath(__file__))
        db_path=path.join(dir_path,"database.db")
        conn=sqlite3.connect(db_path)
        conn.row_factory=sqlite3.Row
        cur=conn.cursor()

    return conn, cur


def db_close(conn,cur):
    conn.commit()
    cur.close()
    conn.close()

@app.route('/')
def index():
    login = session.get('login')
    is_admin = False
    if login:
        
        conn, cur = db_connect()
        if current_app.config['DB_TYPE']=='postgres':
            cur.execute("SELECT * FROM admin WHERE login=%s;", (login,))
        else:
            cur.execute("SELECT * FROM admin WHERE login=?;", (login,))
        admin_user = cur.fetchone()

        if admin_user:
            is_admin = True
        db_close(conn, cur)
    
    return render_template('menu.html', login=login, is_admin=is_admin)

@app.route('/register/')
def register_page():
    return render_template('register.html')

@app.route('/login/')
def login_page():
    return render_template('login.html')
    
@app.route('/admin/')
def admin():
    return render_template('admin.html')

@app.route('/initiative/')
def create_initiative_page():
    return render_template('initiatives.html')

@app.route('/json-rpc-api/', methods=['POST'])
def json_rpc():
    data = request.json
    params = data.get('params')
    id = data.get('id') 

    if data['method'] == 'register':

        login = params.get('login')
        password = params.get('password')
        
        login_pattern = r'^[a-zA-Z0-9]+$'
        if not re.match(login_pattern, login):
            return {
                'jsonrpc': '2.0',
                'error': {
                    'code': 5,
                    'message': 'Логин должен состоять из латинских букв'
                },
                'id': id
            }

        if not password:
            return {
                    'jsonrpc': '2.0',
                    'error': {
                        'code': 1,
                        'message': 'Введите пароль'
                    },
                    'id': id
                }
        password_pattern = r'^(?=.*[a-zA-Z])(?=.*[!@#$%^&*()_+-={}\[\]:;<>,.?/])(?=.*\d).*$'

        if not re.match(password_pattern, password):
            return {
                'jsonrpc': '2.0',
                'error': {
                    'code': 4,
                    'message': 'Пароль должен состоять только из латинских букв, цифр и знаков препинания'
                },
                'id': id
            }

        if len(password) < 8:
            return {
                'jsonrpc': '2.0',
                'error': {
                    'code': 2,
                    'message': 'Длина пароля должна быть больше 8 символов'
                },
                'id': id
            }    
        
        conn, cur = db_connect()

        if current_app.config['DB_TYPE']=='postgres':
            cur.execute("SELECT * FROM users WHERE login=%s;",(login,))
        else:   
            cur.execute("SELECT * FROM users WHERE login=?;",(login,))

        user = cur.fetchone()
            
        if user:
                    db_close(conn, cur) 
                    return {
                    'jsonrpc': '2.0',
                    'error': {
                        'code': 3,
                        'message': 'Пользователь с таким логином уже существует'
                    },
                    'id': id
                }
        hashed_password = generate_password_hash(password)

        if current_app.config['DB_TYPE']=='postgres':
            cur.execute("INSERT INTO users (login, password) VALUES (%s, %s);", (login, hashed_password))  
        else:
            cur.execute("INSERT INTO users (login, password) VALUES (?, ?);", (login, hashed_password)) 
        
        db_close(conn, cur)

        return {
                'jsonrpc': '2.0',
                'result': 'Регистрация успешна',
                'id': id,
        }
    
    elif data['method'] == 'logout':
        session.pop('login', None)

        return {
            'jsonrpc': '2.0',
            'result': 'Вы вышли из системы',
            'id': id
        }
    
    elif data['method'] == 'get_initiatives':
        conn, cur = db_connect()

        params = data.get('params', {})
        offset = params.get('offset', 0) 
        limit = params.get('limit', 20)

        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("SELECT id, topic, text, rating, date FROM initiatives LIMIT %s OFFSET %s;", (limit, offset))
        else:
            cur.execute("SELECT id, topic, text, rating, date FROM initiatives LIMIT ? OFFSET ?;", (limit, offset))

        initiatives = cur.fetchall()
        initiatives = [dict(initiative) for initiative in initiatives]
        db_close(conn, cur)

        return {
            'jsonrpc': '2.0',
            'result': initiatives,
            'id': id
            }

    elif data['method'] == 'login':
        login = params.get('login')  
        password = params.get('password')  

        conn, cur = db_connect()

        if current_app.config['DB_TYPE']=='postgres':
            cur.execute("SELECT * FROM users WHERE login=%s;", (login,))
        else:
            cur.execute("SELECT * FROM users WHERE login=?;", (login,))
        user = cur.fetchone()
        
        if user is None:
            db_close(conn, cur)

            return {
                'jsonrpc': '2.0',
                'error': {
                    'code': 1,
                    'message': 'Неправильный логин или пароль'
                },
                'id': id
            }
        
        if check_password_hash(user['password'], password):  
            session['login'] = login  
            db_close(conn, cur)

            return {
                'jsonrpc': '2.0',
                'result': 'Вход выполнен',
                'id': id,
            }
        else:
            db_close(conn, cur)

            return {
                'jsonrpc': '2.0',
                'error': {
                    'code': 1,
                    'message': 'Неправильный логин или пароль'
                },
                'id': id
            }
        
    elif data['method'] == 'create_initiative':
        topic = params.get('topic')
        text = params.get('text') 

        if not topic or not text:
            return ({'jsonrpc': '2.0', 
                     'error': {
                         'code': 1, 
                         'message': 'Недостаточно данных для создания инициативы'}
            })

        conn, cur = db_connect()
        current_login = session.get('login')

        if current_app.config['DB_TYPE']=='postgres':
            cur.execute("SELECT * FROM users WHERE login=%s;",(current_login,))
        else: 
            cur.execute("SELECT * FROM users WHERE login=?;",(current_login,))

        user = cur.fetchone()
        user_id = user["id"]

        if current_app.config['DB_TYPE']=='postgres':
            cur.execute("INSERT INTO initiatives (user_id,topic, text) VALUES (%s,%s, %s) RETURNING id;", (user_id,topic, text))
            result = cur.fetchone() 
            initiative_id = result["id"] 
        else:
            cur.execute("INSERT INTO initiatives (user_id,topic, text) VALUES (?,?,?);", (user_id,topic, text))
            initiative_id = cur.lastrowid

        db_close(conn, cur)
        
        return ({
            'jsonrpc': '2.0',
            'result': {
                'message': 'Инициатива создана',
                'id': initiative_id
            }
        })
       
    elif data['method'] == 'vote':
        current_login = session.get('login')
        
        if not current_login :
            return {
                        'jsonrpc': '2.0',
                        'error': {
                            'code': 3,
                            'message': 'Пользователь не авторизован'
                        }
                    }
    
        initiative_id = params.get('initiative_id')
        vote = params.get('vote')

        if not initiative_id or not vote:
            return {
                'jsonrpc': '2.0', 
                'error': {'code': 1, 
                        'message': 'Недостаточно данных для голосования'}
                }

        conn, cur = db_connect()

      
        if current_app.config['DB_TYPE']=='postgres':
            cur.execute("SELECT * FROM initiatives WHERE id=%s;", (initiative_id,))
        else: 
            cur.execute("SELECT * FROM initiatives WHERE id=?;", (initiative_id,))
        initiative = cur.fetchone()

        if initiative:
            if vote == 'up':
                if current_app.config['DB_TYPE']=='postgres':
                    cur.execute("UPDATE initiatives SET rating=rating+1 WHERE id=%s;", (initiative_id,))
                else:
                    cur.execute("UPDATE initiatives SET rating=rating+1 WHERE id=?;", (initiative_id,))
            
            elif vote == 'down':
                if current_app.config['DB_TYPE']=='postgres':
                    cur.execute("UPDATE initiatives SET rating=rating-1 WHERE id=%s;", (initiative_id,))
                else:
                    cur.execute("UPDATE initiatives SET rating=rating-1 WHERE id=?;", (initiative_id,))  

            
            if current_app.config['DB_TYPE'] == 'postgres':
                cur.execute("SELECT rating FROM initiatives WHERE id=%s;", (initiative_id,))
            else: 
                cur.execute("SELECT rating FROM initiatives WHERE id=?;", (initiative_id,))

            current_rating_row  = cur.fetchone()
            current_rating = current_rating_row['rating'] if current_rating_row else None
            
            
            if current_rating < -10:
                if current_app.config['DB_TYPE'] == 'postgres':
                    cur.execute("DELETE FROM initiatives WHERE id=%s;", (initiative_id,))
                else:
                    cur.execute("DELETE FROM initiatives WHERE id=?;", (initiative_id,))

                db_close(conn, cur)
                return {'jsonrpc': '2.0', 'result': None}
            
            db_close(conn, cur)
            return ({'jsonrpc': '2.0', 
                     'result': {
                            'rating': current_rating  
                         }})
        
        db_close(conn, cur)
        return ({'jsonrpc': '2.0', 
                'error': {'code': 2, 
                'message': 'Инициатива не найдена'}})
    

    elif data['method'] == 'delete_initiative':
        initiative_id = params.get('initiative_id')
    
        admin_login = session.get('login') 

        if not admin_login:
            return ({
                'jsonrpc': '2.0', 
                'error': {
                    'code': 1, 
                    'message': 'Пользователь не авторизован'
                }
            })

        conn, cur = db_connect()

       
        if current_app.config['DB_TYPE']=='postgres':
            cur.execute("SELECT * FROM initiatives WHERE id=%s;", (initiative_id,))
        else:
            cur.execute("SELECT * FROM initiatives WHERE id=?;", (initiative_id,))    
        initiative = cur.fetchone()

       
        if current_app.config['DB_TYPE']=='postgres': 
            cur.execute("SELECT id FROM admin WHERE login=%s;", (admin_login,))
        else:
            cur.execute("SELECT id FROM admin WHERE login=?;", (admin_login,))   
        admin = cur.fetchone()
        
    
        if admin is not None:
            is_admin = True
        else:
            is_admin = False 

        if is_admin:
           
            if current_app.config['DB_TYPE']=='postgres': 
                cur.execute("DELETE FROM initiatives WHERE id=%s;", (initiative_id,))
            else:   
                cur.execute("DELETE FROM initiatives WHERE id=?;", (initiative_id,))
            db_close(conn, cur) 

            return ({
                        'jsonrpc': '2.0',
                        'result': 'Инициатива успешно удалена'
                    })
        else:
            
            if current_app.config['DB_TYPE']=='postgres': 
                cur.execute("SELECT user_id FROM initiatives WHERE id=%s;", (initiative_id,))
            else:
                cur.execute("SELECT user_id FROM initiatives WHERE id=?;", (initiative_id,)) 
            user_id = cur.fetchone()
                
            if user_id is not None:
                
                if current_app.config['DB_TYPE']=='postgres': 
                    cur.execute("SELECT id FROM users WHERE login=%s;", (admin_login,))
                else:    
                    cur.execute("SELECT id FROM users WHERE login=?;", (admin_login,))
                user = cur.fetchone()
                    
                if user is not None and user['id'] == user_id['user_id']:
                    if current_app.config['DB_TYPE']=='postgres': 
                        cur.execute("DELETE FROM initiatives WHERE id=%s;", (initiative_id,))
                    else:
                        cur.execute("DELETE FROM initiatives WHERE id=?;", (initiative_id,))  
                    
                    db_close(conn, cur) 
                    
                    return ({
                                'jsonrpc': '2.0',
                                'result': 'Инициатива успешно удалена'
                            })
                else:
                    return ({
                            'jsonrpc': '2.0', 
                            'error': {
                                'code': 3, 
                                'message': 'У вас нет прав для удаления этой инициативы'
                            }
                        })
        

    elif data['method'] == 'delete_user':
        current_login = session.get('login')
        user_id = params.get('user_id')
        conn, cur = db_connect()

        if current_app.config['DB_TYPE']=='postgres': 
            cur.execute("DELETE FROM users WHERE id=%s;", (user_id,))
        else:
            cur.execute("DELETE FROM users WHERE id=?;", (user_id,))   
        db_close(conn, cur)
       
        return {
            'jsonrpc': '2.0',
            'result': 'Пользователь успешно удален',
            'id': user_id
        }


    elif data['method'] == 'edit_user':
        current_login = session.get('login')

        user_id = params.get('user_id')
        new_login = params.get('new_login')
        conn, cur = db_connect()

        if not user_id or not new_login:
            db_close(conn, cur)
            
            return {
                'jsonrpc': '2.0',
                'error': {
                    'code': 3,
                    'message': 'Не все данные для редактирования пользователя указаны'
                },
                'id': id
            }
        
        if current_app.config['DB_TYPE']=='postgres': 
            cur.execute("UPDATE users SET login=%s WHERE id=%s;", (new_login, user_id))
        else:
            cur.execute("UPDATE users SET login=? WHERE id=?;", (new_login, user_id))
        db_close(conn, cur)
        
        return {
            'jsonrpc': '2.0',
            'result': 'Учетная запись пользователя успешно обновлена',
            'id': id
        }   
    

    elif data['method'] == 'get_users':
        conn, cur = db_connect()
        
        if current_app.config['DB_TYPE']=='postgres': 
            cur.execute("SELECT id, login FROM users;")
        else:
            cur.execute("SELECT id, login FROM users;")

        users = cur.fetchall()
        users_list = [{'id': user['id'], 'login': user['login']} for user in users]
        db_close(conn, cur)

        return {
            'jsonrpc': '2.0',
            'result': users_list,
            'id': id
        }
    
    
    elif data['method'] == 'login_admin':
        login = params.get('login')  
        password = params.get('password')  

        conn, cur = db_connect()
        
        if current_app.config['DB_TYPE'] == 'postgres':
            cur.execute("SELECT * FROM admin WHERE login=%s;", (login,))
        else:
            cur.execute("SELECT * FROM admin WHERE login=?;", (login,))  
        admin_user = cur.fetchone()
 
        db_close(conn, cur)
        if admin_user and admin_user['password'] == password:

            session['login'] = login  
            return {
                'jsonrpc': '2.0',
                'result': 'Вход выполнен как администратор',
                'id': id,
            }
        else:
            
            return {
                'jsonrpc': '2.0',
                'error': {
                    'code': 1,
                    'message': 'Неправильный логин или пароль'
                },
                'id': id
            }

        
    elif data['method'] == 'delete_account':
        login = session.get('login')
        confirm = data['params']['confirm']

        conn, cur = db_connect()

        if current_app.config['DB_TYPE']=='postgres':
            cur.execute("SELECT * FROM users WHERE login=%s;", (login,))
        else:
            cur.execute("SELECT * FROM users WHERE login=?;", (login,))    
        user = cur.fetchone()

        if confirm == 'yes':
            if current_app.config['DB_TYPE']=='postgres':
                cur.execute("DELETE FROM users WHERE login=%s;", (login,))
            else:    
                cur.execute("DELETE FROM users WHERE login=?;", (login,))
            session.clear()
            
            db_close(conn, cur)
            
            return {
                'jsonrpc': '2.0',
                'result': True,
                'id': data['id']
            }
        
        else:
            
            db_close(conn, cur)
            return {
                'jsonrpc': '2.0',
                'error': {
                    'code': 1,
                    'message': 'Удаление аккаунта отменено'
                },
                'id': data['id']
            }
    
    return{
        'jsonrpc': '2.0',
        'error':{
            'code': -32601,
            'message': 'Method not found'
        },
        'id': id
    }
