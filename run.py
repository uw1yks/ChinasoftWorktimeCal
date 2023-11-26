import random
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5
import urllib.parse
from Crypto.Util.Padding import pad
import requests
from datetime import date, datetime, timedelta

username = ''
password = ''


def generate_random_bytes(length):
    char_set = [
        ord(c) for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789']
    return bytes(random.choice(char_set) for _ in range(length))


def rsa_encrypt(public_key, plaintext):
    public_key_der = base64.b64decode(public_key)
    key = RSA.importKey(public_key_der)
    cipher = PKCS1_v1_5.new(key)
    ciphertext = cipher.encrypt(plaintext)
    encrypted_data = base64.b64encode(ciphertext).decode('utf-8')
    return urllib.parse.quote(encrypted_data)


def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)

    padded_plaintext = pad(plaintext.encode(
        'utf-8'), AES.block_size, style='pkcs7')
    ciphertext = cipher.encrypt(padded_plaintext)
    encrypted_data = base64.b64encode(ciphertext).decode('utf-8')
    return urllib.parse.quote(encrypted_data)


def get_public_key():
    public_key_url = 'https://ics.chinasoftinc.com/r1portal/getPublicKey'
    response = requests.get(public_key_url)
    public_key = response.json()['data']['rsaPublicKey']
    return public_key


def init():
    aes_key = generate_random_bytes(16)
    public_key = get_public_key()
    encrypted_aes_key = rsa_encrypt(public_key, aes_key)
    encrypted_username = aes_encrypt(username, aes_key)
    encrypted_password = aes_encrypt(password, aes_key)
    return encrypted_aes_key, encrypted_username, encrypted_password


def login():
    login_url = 'https://ics.chinasoftinc.com/r1portal/login'
    data = {
        'userName': encrypted_username,
        'password': encrypted_password,
        'encryptKey': encrypted_aes_key,
        'headAgreement': 'https'
    }
    login_response = session.post(url=login_url, data=data)
    return login_response


def get_empCode():
    emp_url = "https://yihr.chinasoftinc.com:18010/sso/toLogin"
    emp_response = requests.get(
        url=emp_url, allow_redirects=False, cookies=session.cookies)
    location_url = emp_response.headers['Location']

    start_index = location_url.find('empCode=') + len('empCode=')
    emp_code = location_url[start_index:]
    return emp_code


def get_userToken(emp_code):
    login_by_empCode_url = 'https://yihr.chinasoftinc.com:18010/ehr_saas/web/user/loginByEmpCode.jhtml'
    params = {
        'app': 'pc',
    }

    json_data = {
        'empCode': emp_code,
    }

    userToken_response = session.post(
        url=login_by_empCode_url, params=params, json=json_data, cookies=session.cookies)

    userToken = userToken_response.json()['result']['data']['token']
    return userToken


def get_check_time(token, date):
    get_att_emp_log_url = 'https://yihr.chinasoftinc.com:18010/ehr_saas/web/attEmpLog/getAttEmpLogByEmpId2.empweb?'
    headers = {
        'Content-Type': 'application/json;charset=UTF-8',
        'token': token,
    }
    json_data = {
        'dt': date,
    }

    att_response = session.post(
        url=get_att_emp_log_url, headers=headers, json=json_data, cookies=session.cookies)

    dtDetailList = att_response.json(
    )['result']['data']['attEmpDetail']['dtDetailList']

    check_in = dtDetailList[0]["checkIn"]
    check_out = dtDetailList[0]["checkOut"]

    if ('未打卡' != check_in or '未打卡' != check_out):
        check_in_time_str = check_in.split("(")[1].rstrip(")")
        check_out_time_str = check_out.split("(")[1].rstrip(")")

        return check_in_time_str, check_out_time_str
    return 0, 0


def calculate_work_duration(check_in_str, check_out_str):
    # 定义上班、下班和午休的时间点
    work_start = datetime.strptime("08:00:00", "%H:%M:%S")
    lunch_start = datetime.strptime("12:00:00", "%H:%M:%S")
    lunch_end = datetime.strptime("13:30:00", "%H:%M:%S")
    work_end = datetime.strptime("17:30:00", "%H:%M:%S")
    overtime_start = datetime.strptime("18:00:00", "%H:%M:%S")

    # 解析打卡时间
    check_in_time = datetime.strptime(check_in_str, "%H:%M:%S")
    check_out_time = datetime.strptime(check_out_str, "%H:%M:%S")

    # 考虑特殊规则调整打卡时间
    check_in_time = max(check_in_time, work_start)
    check_out_time = min(
        check_out_time, work_end) if check_out_time <= overtime_start else check_out_time

    # 计算工作时长
    work_duration = timedelta(0)
    if check_in_time < lunch_start:
        # 计算上午工作时长
        morning_work_end = min(check_out_time, lunch_start)
        work_duration += morning_work_end - check_in_time

    if check_out_time > lunch_end:
        # 计算下午工作时长
        afternoon_work_start = max(check_in_time, lunch_end)
        if check_out_time > overtime_start:
            work_duration += work_end - afternoon_work_start + check_out_time - overtime_start
        elif check_out_time > work_end:
            work_duration += work_end - afternoon_work_start
        else:
            work_duration += check_out_time - afternoon_work_start

    return work_duration


if __name__ == '__main__':
    encrypted_aes_key, encrypted_username, encrypted_password = init()
    session = requests.session()
    login()
    emp_code = get_empCode()
    user_token = get_userToken(emp_code)

    today = date.today()
    work_days = 0
    total_work_duration = timedelta(0)

    for day in range(1, today.day):
        date_str = today.replace(day=day).strftime("%Y-%m-%d 00:00:00")
        check_in_time_str, check_out_time_str = get_check_time(
            user_token, date_str)
        if (check_in_time_str != 0 and check_in_time_str != 0):
            work_days += 1
            work_duration = calculate_work_duration(
                check_in_time_str, check_out_time_str)
            total_work_duration += work_duration
            print(
                f"{date_str.split(' ')[0]} 上班时间：{check_in_time_str} 下班时间：{check_out_time_str} 工作时长: {work_duration}")

    total_work_hours = round(total_work_duration.total_seconds() / 3600, 2)

    average_work_hours = round(
        (total_work_duration / work_days).total_seconds() / 3600, 2) if work_days > 0 else 0

    print()
    print(f"本月应达工作时长：{8*work_days} 小时")
    print(f"本月总工作时长: {total_work_hours} 小时")
    print(f"日均工作时长: {average_work_hours} 小时")
