import urllib2 

body = urllib2.urlopen('http://www.nostarch.com')

print body.read()
