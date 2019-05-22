# This module requires katana framework 
# https://github.com/PowerScript/KatanaFramework

# :-:-:-:-:-:-:-:-:-:-:-:-:-:-:-:-:-: #
# Katana Core import                  #
from core.KatanaFramework import *    #
# :-:-:-:-:-:-:-:-:-:-:-:-:-:-:-:-:-: #

# LIBRARIES 
from scapy.all import *
import urllib2,json
import pyperclip
# END LIBRARIES 

# END LIBRARIES 
def init():
	init.Author             ="RedToor"
	init.Version            ="1.5"
	init.Description        ="Omegle.com User tracker"
	init.CodeName           ="web/omg.track"
	init.DateCreation       ="03/08/2016"      
	init.LastModification   ="21/06/2019"
	init.References         =None
	init.License            =KTF_LINCENSE
	init.var                ={}

	# DEFAULT OPTIONS MODULE
	init.options = {
		# NAME       VALUE               RQ     DESCRIPTION
		'interface' :[INTERFACE_ETHERNET,True ,'Monitor Interface']
	}
	
	init.aux = "\n Devices Founds: "+str(NET.GetInterfacesOnSystem())+"\n"
	return init
# END INFORMATION MODULE
IPList=[]
# CODE MODULE    ############################################################################################
def main(run):
	
	if NET.CheckIfExistInterface(init.var['interface']):
		while True:sniff(filter="udp", prn=callback, store=0, iface=init.var['interface'])

# END CODE MODULE ############################################################################################

def callback(pkt):
	
	try:
		for IPcheck in IPList:
			if IPcheck == str(pkt[IP].dst): return
		IPList.append(str(pkt[IP].dst))
		u = urllib2.urlopen("http://ip-api.com/json/"+pkt[IP].dst)
		data_string = json.loads(u.read())
		Country=data_string["country"]
		City=data_string["city"]
		Region=data_string["regionName"]
		ZIP=data_string["zip"]
		
		output=("    | IP => "+pkt[IP].dst+" Country => "+Country+" City => "+City+", "+Region+" ZIP => "+ZIP)

		f=open('/home/vanish/Desktop/log', 'a')
		f.write(output)
		f.write('\n')
		f.close()

		pyperclip.copy(output)


		return output
	except:n=None
