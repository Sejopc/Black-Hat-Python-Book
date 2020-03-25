import re # Regex
import zlib
import cv2 # OpenCV - For Human Facial Recognition on Images
from scapy.all import *

pictures_directory  = "/root/Documents/Black-Hat-Python-Book/Chapter 4/pictures"
faces_directory     = "/root/Documents/Black-Hat-Python-Book/Chapter 4/faces"
pcap_file           = "arper3.pcap"

def get_http_headers(http_payload):
    
    try:
        # split the HTTP headers off if it is HTTP traffic (there will be a \r\n\r\n after the HTTP response headers, right before the payload body)
        headers_raw = http_payload[:http_payload.index("\\r\\n\\r\\n")+4]
        #print(headers_raw)
        #print("-----")
        #break out the headers into a dictionary called 'headers'
        headers = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\\r\\n", headers_raw)) # This was challenging to understand, but now I do, and is simply. The 'r' at the start of the pattern string designates a python "raw" string which                                                                                     # passes through backslashes without change which is very handy for regular expressions. I recommend that you always write pattern strings with the 'r'                                                                                    # just as a habit.
                                                                                    # (?P<name) and (?P<value>) are just Python extensions to re module to match by
                                                                                    # group name instead of numbers. To understand read: https://docs.python.org/3/howto/regex.html#non-capturing-and-named-groups 
                                                                                    # And for more general information on re.findall() function and understand this specific Regex, read: https://developers.google.com/edu/python/regular-                                                                                    # expressions#findall-and-groups.
        # Ultimately, above re.findall function will return a list of tuples, which will be converted into a dictionary, i.e:
        # [('Content-Type'), ('image/png')]
        # [('Host'), ('example.com')]
        # ...etc for every single header, and then turn them into a Dictionary, i,e:
        # {'Content-Type':'image/png', 'Host':'example.com', etc... }
    except:
        return None
    
    return headers

def extract_image(headers, http_payload):
    image       = None
    image_type  = None

    try:
        if "image" in headers['Content-Type']:
        
            # Grab the image type and image body
            image_type = headers['Content-Type'].split("/")[1]
            image = http_payload[http_payload.index("\\r\\n\\r\\n")+8:]
            print("IMAGE TYPE: " + image_type)
            print("IMAGE PAYLOAD - FIRST 100 CHARS: " + image[:100])

            # If we detect compression, decompress the image
            try:
                if "Content-Encoding" in headers.keys():
                    if headers['Content-Encoding'] == "gzip":
                        image = zlib.decompress(image, 16+zlib.MAX_WBITS)
                    elif headers['Content-Encoding'] == "deflate":
                        image = zlib.decompress(image)
            except:
                pass
    except:
        return None, None

    return image, image_type

def face_detect(path, file_name):
        
    img     = cv2.imread(path)
    cascade = cv2.CascadeClassifier("haarcascade_frontalface_alt.xml")
    rects   = cascade.detectMultiScale(img, 1.3, 4, cv2.cv.CV_HAAR_SCALE_IMAGE, (20,20))

    if len(rects) == 0:
        return False

    rects[:, 2:] += rects[:, :2]

    # highlight the faces in the image
    for x1,y1,x2,y2 in rects:
        cv2.rectangle(img, (x1,y1), (x2,y2), (127,255,0), 2)

    cv2.imwrite("%s/%s-%s" % (faces_directory, pcap_file, file_name), img)
    
    return True

def http_assembler(pcap_file):

    carved_images = 0
    faces_detected = 0

    a = rdpcap(pcap_file) # Read pcap. We open up the pcap for processing.
    sessions = a.sessions() # Separates each TCP, UDP, ICMP, IP session into a dictionary
    
    for session in sessions: # each TCP, UDP, ICMP, IP session contains several packets (like when you right click and Follow TCP Stream in Wireshark), so we inspect each packet from a given session, each time.

        http_payload = ""
        #print(session[session])
        for packet in sessions[session]:
            try:
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    #print(packet[TCP].payload)
                    #print("-----")
                    # reassemble the tcp stream
                    http_payload += str(packet[TCP].payload)
                    #print(http_payload)
                    #print('---')
            except:
                pass

        headers = get_http_headers(http_payload)
        #print(headers)
        #print('----')

        if headers is None:
            continue

        image, image_type = extract_image(headers, http_payload)
        
        if image is not None and image_type is not None:
            # store the image
            file_name = "%s_pic_carver_%d.%s" % (pcap_file, carved_images, image_type)
            fd = open("%s/%s" % (pictures_directory, file_name), "w")
            fd.write(image)
            fd.close()

            carved_images += 1

            # now attempt face detection
            try:
                result = face_detect("%s/%s" % (pictures_directory, file_name), file_name)
                if result is True:
                    faces_detected += 1
            except:
                pass
        
    return carved_images, faces_detected

carved_images, faces_detected = http_assembler(pcap_file)

print("Extracted %d images" % carved_images)
print("Extracted %d faces" % faces_detected)
