#-*- coding: utf-8 -*-
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

import time
import re
import os
import json
from datetime import datetime
import logging
import random
from string import letters
import hashlib
import hmac

import urllib2
from xml.dom import minidom


import webapp2
import jinja2

from google.appengine.api import memcache
from google.appengine.ext import ndb

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape=True)


secret = 'difhwl6@09$$.t0g'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key.id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))


##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

class User(ndb.Model, BlogHandler):
    name = ndb.StringProperty(required = True)
    pw_hash = ndb.StringProperty(required = True)
    email = ndb.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls, name):
        u = User.query().filter(User.name == name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    def get(self):
    	if self.user:
    		self.redirect('/blog')

        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "사용할 수 없는 아이디입니다."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "사용할 수 없는 비밀번호입니다."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "비밀번호가 일치하지 않습니다."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "가능하지 않은 이메일 주소입니다."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = '사용자가 이미 존재합니다'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)

            u.put()

            self.login(u)
            self.redirect('/blog')

class Login(BlogHandler):
    def get(self):
    	if self.user:
    		self.redirect('/blog')

        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = '로그인에 실패했습니다'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')


GMAPS_URL = "https://maps.googleapis.com/maps/api/staticmap?&size=380x360&sensor=false&"
def gmap_img(points):
	markers = "markers="
	if points:
		markers += '&'.join("%s,%s" % (p.lat, p.lon) for p in points)
	return GMAPS_URL + markers


STATIC_URL = "http://ip-api.com/xml/"
def get_coords(IP):
	IP = "123.109.213.85"
	URL = STATIC_URL + IP

	xmlData = None
	p = urllib2.urlopen(URL).read()
	xmlData = minidom.parseString(p)

	lat, lon = None, None
	if xmlData.getElementsByTagName("lat"):
		if xmlData.getElementsByTagName("lat")[0].childNodes[0].nodeValue:
			lat = xmlData.getElementsByTagName("lat")[0].childNodes[0].nodeValue
	if xmlData.getElementsByTagName("lon"):
		if xmlData.getElementsByTagName("lon")[0].childNodes[0].nodeValue:
			lon = xmlData.getElementsByTagName("lon")[0].childNodes[0].nodeValue
	if lat is not None and lon is not None:
		return ndb.GeoPt(lat, lon)


class Post(ndb.Model, BlogHandler):
	subject = ndb.StringProperty(required=True)
	content = ndb.StringProperty(required=True)
	created = ndb.DateTimeProperty(auto_now_add=True)
	last_modified = ndb.DateTimeProperty(auto_now=True)
	coords = ndb.GeoPtProperty()

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return self.render_str("post.html", p = self)


def convertToSerializable(data):
	result = data.to_dict()
	record = {}

	for key in result.iterkeys():
		if isinstance(result[key], datetime):
			record[key] = result[key].isoformat()
			continue
		record[key] = result[key]

		record['key'] = data.key.id()

	return record

def filter_results(query):
	result = []

	if type(query) != list:
		record = convertToSerializable(query)
		return record

	for q in query:
		result.append(convertToSerializable(q))

	return result


class BlogJSON(BlogHandler):
	def get(self):
		posts = Post.query().fetch()
		serializedResults = filter_results(posts)

		self.response.headers['Content-Type'] = 'application/JSON'
		self.write(json.dumps(serializedResults))
		

class PostJSON(BlogHandler):
	def get(self, post_id):
		post = Post.get_by_id(int(post_id))
		serializedResults = filter_results(post)

		self.response.headers['Content-Type'] = 'application/JSON'
		self.write(json.dumps(serializedResults))


def each_post(post_id):
	key = post_id

	postAndTime = memcache.get(key)

	if postAndTime is None:
		logging.error("a POST DB QUERY")
		post = Post.get_by_id(int(post_id))
		now = datetime.now()
		postAndTime = [post, now]

		memcache.set(key, postAndTime)

	return postAndTime


def top_posts(update=None):
	key = 'top'

	postsAndTime = memcache.get(key)

	if postsAndTime is None or update:
		logging.error("ALL POSTS DB QUERY")
		
		posts = Post.query().order(-Post.created)
		posts = list(posts)
		now = datetime.now()
		postsAndTime = [posts, now]

		memcache.set(key, postsAndTime)

	return postsAndTime


class FlushPage(BlogHandler):
	def get(self):
		memcache.flush_all()

		self.redirect('/blog')


class MainPage(BlogHandler):
	def get(self):
		self.redirect('/blog')

class BlogPage(BlogHandler):
	def get(self):
		postsAndTime = top_posts()

		posts = postsAndTime[0]
		last_queried = postsAndTime[1]

		gmap_url = None
		points = filter(None, (p.coords for p in posts))

		gmap_url = gmap_img(points)

		duration = int((datetime.now() - last_queried).total_seconds())
		self.render("front.html", posts=posts, duration = duration, 
			user = self.user, gmap_url=gmap_url)


class NewPost(BlogHandler):
	def get(self):
		if self.user:
			self.render("newpost.html",user=self.user)
		else:
			self.redirect("/login")
		

	def post(self):
		if not self.user:
			self.redirec('/blog')

		subject = self.request.get("subject")
		content = self.request.get("content")

		if subject and content:
			p = Post(subject=subject, content=content)
			coords = get_coords(self.request.remote_addr)
			if coords:
				p.coords = coords

			p_key = p.put()

			top_posts(True)
			
			self.redirect('/post/%s' % str(p_key.id()))

		else:
			error = "제목과 내용을 둘 다 입력하세요"
			self.render("newpost.html", subject=subject, content=content, error=error)


class PostPage(BlogHandler):
	def get(self, post_id):
		postAndTime = each_post(post_id)

		if not postAndTime:
			self.error(404)
			return

		post = postAndTime[0]
		last_queried = postAndTime[1]
		duration = int((datetime.now() - last_queried).total_seconds())


		gmap_url = None
		point = [post.coords]
		gmap_url = gmap_img(point)
		
		self.render("permalink.html", post=post, 
			duration = duration, user=self.user, gmap_url=gmap_url)



app = webapp2.WSGIApplication([
	('/', MainPage),
	('/blog', BlogPage),
	('/newpost', NewPost),
	('/post/([0-9]+)', PostPage),
	('/signup', Register),
	('/login', Login),
	('/logout', Logout),
	('/.json', BlogJSON),
	('/post/([0-9]+).json', PostJSON),
	('/flush', FlushPage),
	], debug=True)
