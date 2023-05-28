from flask import Flask, render_template, request, jsonify, redirect, url_for
from pymongo import MongoClient
import requests
import hashlib
import jwt
import datetime
import random
from datetime import datetime, timedelta
from bs4 import BeautifulSoup

app = Flask(__name__)

client = MongoClient('mongodb://ddarong:darong2@3.38.152.118',27017)
db = client.dbweek00

SECRET_KEY = 'JungleFood'


@app.route('/')
def login():
    return render_template('login.html')


@app.route('/sign_up')
def sign_up():
    return render_template('sign_up.html')


@app.route('/api/sign_up', methods=['POST'])
def api_register():
    id_receive = request.form['user_id']
    pw_receive = request.form['password']
    phone_receive = request.form['phoneNumber']

    id_check = db.user.find_one({'id': id_receive})

    if id_check != None:
        return jsonify({'result': 'fail', 'msg': '이미 존재하는 아이디입니다.'})
    else:
        pw_hash = hashlib.sha256(pw_receive.encode('utf-8')).hexdigest()

        db.user.insert_one(
            {'id': id_receive, 'pw': pw_hash, 'phone': phone_receive})

        return jsonify({'result': 'success'})


@app.route('/api/login', methods=['POST'])
def api_login():
    id_receive = request.form['id_give']
    pw_receive = request.form['pw_give']

    # 회원가입 때와 같은 방법으로 pw를 암호화합니다.
    pw_hash = hashlib.sha256(pw_receive.encode('utf-8')).hexdigest()

    # id, 암호화된pw을 가지고 해당 유저를 찾습니다.
    result = db.user.find_one({'id': id_receive, 'pw': pw_hash})

    # 찾으면 JWT 토큰을 만들어 발급합니다.
    if result is not None:
        # JWT 토큰에는, payload와 시크릿키가 필요합니다.
        # 시크릿키가 있어야 토큰을 디코딩(=풀기) 해서 payload 값을 볼 수 있습니다.
        # 아래에선 id와 exp를 담았습니다. 즉, JWT 토큰을 풀면 유저ID 값을 알 수 있습니다.
        # exp에는 만료시간을 넣어줍니다. 만료시간이 지나면, 시크릿키로 토큰을 풀 때 만료되었다고 에러가 납니다.
        payload = {
            'id': id_receive,
            'exp': datetime.utcnow() + timedelta(seconds=600)  # 언제까지 유효한지 6000 은 1시간
        }
        # jwt를 암호화
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

        # token을 줍니다.
        return jsonify({'result': 'success', 'token': token})
    # 찾지 못하면
    else:
        return jsonify({'result': 'fail', 'msg': '아이디/비밀번호가 일치하지 않습니다.'})

# 쿠키를 받아와서 블랙리스트에 토큰 등록


# @app.route('/api/logout')
# def api_logout():
#     token_receive = request.cookies.get('mytoken')
#     blacktoken = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
#     blacklist = {"blacktoken": blacktoken}
#     db.black.insert_one(blacklist)

#     return redirect(url_for("login"))

@app.route('/api/logout')
def api_logout():

    try:
        token_receive = request.cookies.get('mytoken')
        blacktoken = jwt.decode(
            token_receive, SECRET_KEY, algorithms=['HS256'])
        blacklist = {"blacktoken": blacktoken}
        db.black.insert_one(blacklist)

        return redirect(url_for("login"))

  # 만약 해당 token의 로그인 시간이 만료되었다면, 아래와 같은 코드를 실행합니다.
    except jwt.ExpiredSignatureError:
        return redirect(url_for("login", msg="로그아웃 되었습니다."))
  # 만약 해당 token이 올바르게 디코딩되지 않는다면, 아래와 같은 코드를 실행합니다.
    except jwt.exceptions.DecodeError:
        return redirect(url_for("login", msg="로그인 정보가 존재하지 않습니다."))


@app.route('/main')
def home():
    token_receive = request.cookies.get('mytoken')
    try:
        unknown_token = jwt.decode(
            token_receive, SECRET_KEY, algorithms=['HS256'])
        user_info = db.user.find_one({"id": unknown_token['id']})
        blacklist = db.black.find_one({"blacktoken": unknown_token})
        if blacklist is None:
            ran_num1 = random.randrange(1, 11)
            ran_num2 = random.randrange(1, 11)
            result2 = list(db.rank.find({}, {'_id': 0}))
            top_rank1 = result2[ran_num1]['topurl']
            top_rank2 = result2[ran_num2]['topurl']
            top_add1 = result2[ran_num1]['top_adress']
            top_add2 = result2[ran_num2]['top_adress']
            top_name1 = result2[ran_num1]['top_name']
            top_name2 = result2[ran_num2]['top_name']
            return render_template('index.html', url1=top_rank1, url2=top_rank2, add2=top_add2, add1=top_add1,  name2=top_name2, name1=top_name1, template_name=user_info['id'])
            # return render_template("index.html", template_name=user_info['id'])
        else:
            return redirect(url_for("login"))

  # 만약 해당 token의 로그인 시간이 만료되었다면, 아래와 같은 코드를 실행합니다.
    except jwt.ExpiredSignatureError:
        return redirect(url_for("login", msg="로그인 시간이 만료되었습니다."))
  # 만약 해당 token이 올바르게 디코딩되지 않는다면, 아래와 같은 코드를 실행합니다.
    except jwt.exceptions.DecodeError:
        return redirect(url_for("login", msg="로그인 정보가 존재하지 않습니다."))


@app.route('/crew', methods=['POST'])
def crew():
    token_receive = request.headers['token_give']
    title_receive = request.form['title_give']

    payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])

    userinfo = db.user.find_one({'id': payload['id']})

    result = list(db.register.find({'title': title_receive}, {'_id': 0}))
    realnumtemp = result[0]['realnum']
    maxnumtemp = result[0]['maxnum']

    if int(maxnumtemp) > int(realnumtemp):
        # print(db.cardjinho.find({'title': title_receive}, {'_id': 0}))

        db.register.update_one({'title': title_receive}, {
                               "$inc": {'realnum': 1}})

        realnum = realnumtemp+1
        idtemp = 'id' + str(realnum)
        phonetemp = 'phone' + str(realnum)

        # print(idtemp)

        db.register.update_one({'title': title_receive}, {
                               "$set": {idtemp: userinfo['id'], phonetemp: userinfo['phone']}})

    # db.crew.insert_one({'id':userinfo['id'], 'phone':userinfo['phone']})

    return jsonify({'result': 'success', 'name': userinfo['id'], 'phone': userinfo['phone']})

@app.route('/crew/check', methods=['POST'])
def crew_check():
    title_receive = request.form['title_give']
    totalList=[]
    ttotalList=[]
    result = db.register.find_one({'title': title_receive}, {'_id': 0})
    rresult = result['realnum'] # realnum
    for i in range(rresult):
      k = i + 1
      idNum = 'id'+ str(k)
      phoneNum = 'phone'+ str(k)
      # print(idNum)
      total = ' '+result[idNum]+'   '+result[phoneNum]

      totalList.append(total)



   #  totalresult = result['totalInfo']
   #  print(totalresult)
    return jsonify({'result': 'success', 'total':totalList})

   #  idlist=[]
   #  phonelist=[]
   #  for i in range(0,int(realnumtemp)):
   #      # print(i)
   #      realnum=i+1
   #      idtemp = 'id' + str(realnum)
   #      phonetemp = 'phone' + str(realnum)
   #      # print(idtemp)
   #      i=i+1
   #      id=result[0][idtemp]
   #      phone=result[0][phonetemp]
   #      # print(id)
   #      # print(phone)
        
      #   idlist.append(id)
      #   phonelist.append(phone)



@app.route('/memo', methods=['POST'])
def post_information():

    token_receive = request.headers['token_give']
    # print(token_receive)
    payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
    # print(payload)
    userinfo = db.user.find_one({'id': payload['id']}, {'_id':0, 'pw':0})

    # 1. 클라이언트로부터 데이터를 받기
    try:
        title_receive = request.form['title_give']
        url_receive = request.form['url_give']
        maxnum_receive = request.form['maxnum_give']
        date_receive = request.form['date_give']
        time_receive = request.form['time_give']

        webpage = requests.get(url_receive, verify=False)
        soup = BeautifulSoup(webpage.content, "html.parser")
        sign_board = soup.select_one('head > meta:nth-child(4)')['content']
        address = soup.select_one('head > meta:nth-child(6)')['content']

        information = {'title': title_receive,  'maxnum': maxnum_receive,
                       'date': date_receive, 'time': time_receive, 'url': url_receive, 'sign': sign_board, 'address': address
                       , 'realnum':1, 'id1': userinfo['id'], 'phone1': userinfo['phone']}
        db.register.insert_one(information)

        return jsonify({'result': 'success'})
    except requests.exceptions.InvalidURL:
        return jsonify({'result': 'fail', 'msg': '카카오 맵 URL을 올려주세요'})
    except requests.exceptions.MissingSchema:
        return jsonify({'result': 'fail', 'msg': '카카오 맵 URL을 올려주세요'})



@app.route('/memo', methods=['GET'])
def read_register():
    result = list(db.register.find({}, {'_id': 0}))
    return jsonify({'result': 'success', 'register': result})


# 로그인 만료 (크루 등록이나 코멘트 작성)
# @app.route('/user', methods=['GET'])
# def api_valid():
#     token_receive = request.headers['token_give']

#     try:
#         payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])

#         userinfo = db.user.find_one({'id':payload['id']})

#         return jsonify({'result':'success','name':userinfo['id']})
#     except jwt.ExpiredSignatureError:
#         return jsonify({'result':'fail','msg':'로그인이 만료되었습니다.'})
if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)