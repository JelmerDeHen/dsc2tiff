#!/usr/bin/python

import sys
sys.path.append("/home/system/pentest/libz/all-libs/")

import shutil
import sys,re,os,time,datetime,random

from utils.highFsInspector import HFS

from decimal import *

import goodies.progress as progress
import goodies.color as color

#import ext_mysql

import pyPdf

from dbgTools.dbg import DBG

from conf.settings import *
from specific.decos.qr import DSC_QR

class DSC:
	dsc =	''
	fp =	None
	globalHeader = ''
	stats = {
		'filecounter':	0,
		'bytecount':	0,
		'seqNos':	{},
		'hdrCnt':	0
	}

	errors = {
		1:	'Input file is not DSC',
		2:	'Notice: This header does not contain a CCITT 4 TIFF header!',
		3:	'Decodng the global DSC header gave an exception',
		4:	'Could not automatically determine the amount of characters for a property in the global DSC header',
		5:	'[!] The advanced DSC check failed'
	}


	# Global header offset, may be influenced by errors in the header
	globalHdrOffset = 0

	def __init__(self,dscFile=''):
		self.DBG = DBG()
		self.hfs = HFS()
		self.qr = DSC_QR()

		if dscFile != '':
			self.dsc = dscFile
		else:
			self.dsc = ''
	def checkDSCprefixBytes(self, globalHeader):
		# Change the global header offset, no DSC prefix bytes means 2 bytes shorter global header
		if globalHeader[0:2]=='\x0d\x0a':
			print '[+] Substracting 2 bytes from global header because the DSC prefix bytes are missing'
			self.globalHdrOffset = self.globalHdrOffset-2

		if globalHeader[0:2]=='\x90\x03':
			return True
		else:
			return True
			# To make this fatal uncomment the following line
			#return False

	def getDSCExportVersion(self, globalHeader):
		ver = re.findall("Decos Post scan file version ([\.0-9]*?)\r\n",globalHeader)[0]
		return ver

	def isDSC(self, filename=''):
		# is filename or self.dsc a DSC file?
		if filename=='':
			# Switch to self.dsc
			filename = self.dsc

		if filename=='':
			return False

		if self.hfs.isFile(filename)==False:
			return False
		
		# Make a file pointer
		try:
			self.fp = open(filename, "r")
		except:
			return False

		# Get the globalHeader
		globalHeader = self.fp.read(600)#~490 is ok but this is just in case things are slightly different
		#print globalHeader	
		#print self.getDSCExportVersion(globalHeader)
		#print self.checkDSCprefixBytes(globalHeader)

		if self.checkDSCprefixBytes(globalHeader)==False:
			self.DBG.rLog(filename+' does not contain prefix bytes')
			# If you want to make this fatal, uncomment the following line
			#return False

		if self.getDSCExportVersion(globalHeader)!='1.1':
			return False

		self.globalHeader = globalHeader
		return True

	def crawlDSCHeader(self, action):

		if self.isDSC() == False:
			return 1

		# Get the header info from self.globalHeader (assigned in isDSC())
		CCITT4TiffHeader = re.findall("CCITT 4 TIFF\r\nHeaders of the following type:\r\nDecos Post tiff-file header \r\n([\s\S]*?)(?:\r\n){2}",self.globalHeader)
		if len(CCITT4TiffHeader)!=1:
			return 2
		CCITT4TiffHeader=CCITT4TiffHeader[0]

		# Split it by lines
		CCITTHeaderLines = re.findall('([^\r\n]+)',CCITT4TiffHeader)

		# Find out the configuration for this file
		headerConfig = {
			0:{
				'len':29,
				'description':'prefix line'
			}
		}

		counter=1
		for CCITTHeaderLine in CCITTHeaderLines:
			
			isitfirstline = CCITTHeaderLine.split(":")
			if len(isitfirstline)==2:
				lineName = isitfirstline[0].replace(' ','')
				number = re.findall("\d+",isitfirstline[1])
				if len(number)==1:
					number = number[0]
					if lineName!="Type" and counter!=8:# omit the 1 byte count and len=10;name=length at the end
						headerConfig[counter]={
							'len':int(number),
							'description':lineName
						}
						counter+=1
				else:
					return 4
			else:
				return 3
	
		# Here comes a test to see if the DSC header follows up with a file header
		# DSC file prefix			2
		# DSC version+global header prefix	112
		# CCITT4Tiff Header length		varies
		# global header suffix			38
		# Align fp +1?				1
		if self.globalHdrOffset!=0:
			print 'Global header offset set'
		globalHeaderLength = 2+112+len(CCITT4TiffHeader)+38+1+self.globalHdrOffset
		self.fp.seek(globalHeaderLength)
		#print self.fp.read(50)
		if self.fp.read(5)!='Decos':
			return 5
	
		# Get the file size; resets fp to 0
		fileSize = self.hfs.getFileSize(self.fp)
		self.dscSize = fileSize

		# Get the header length of files, this is required for knowing how much we have to cut off at the beginning
		self.defaultFileHeaderLen = 0
		for keyIndex in headerConfig:
			self.defaultFileHeaderLen += headerConfig[keyIndex]['len']
	
		self.fp.seek(globalHeaderLength)# Align fp to first file header

		#a = decodeDecosDSC(method, fh,headerConfig,header_totalLen,srcFileOnDisk,fileSize,globalHeaderLength)
		#self.DBG.dbg('Calling crawlFilesInDsc','crawlDSCHeader')
		self.globalHeaderLength = globalHeaderLength
		self.crawlFilesInDsc(
			action,
			globalHeaderLength,
			headerConfig,
			fileSize
		)

		# At this point we got details in the following locations:
		# -> header length inside header_totalLen as int
		# -> total amount of bytes inside DSC file inside fileSize; divide by 1024 2 times to get MB's

		a = 0
		if a==0:
			return 0,'TODOooo'#collectionRoot
		else:
			return a,'TODOOo'#collectionRoot

	def R2D2_last_good_ptr_method(self, ptrHist, fileSize):
		#.#.# Find the last good pointer
		lastPtrs = ptrHist[-10:]
		lastPtrs.reverse()

		lastGoodPtr = 0
		for ptr in lastPtrs:
			self.fp.seek(ptr)
			currData = self.fp.read(self.defaultFileHeaderLen)
			if currData[0:5]=='Decos':
				lastGoodPtr = ptr	
				break
		if lastGoodPtr==0:
			return 0,0
		#.#.#

		#,#,# Manually find the next good header
		spinByteJumpNext = 1024*1024*2
		nextHeaderLocation = 0
		chunk = ''
		while self.fp.tell()!=fileSize:
			#if spinByteJumpNext<(fileSize-self.fp.tell()):
			#	spinByteJumpNext = fileSize-self.fp.tell()

			chunk = self.fp.read(spinByteJumpNext)

			hit = chunk.find('Decos Post tiff-file header')
			if hit>-1:
				nextHeaderLocation = self.fp.tell()-spinByteJumpNext+hit
				break

		if nextHeaderLocation==0:
			return 0,0

		
		#,#,#

		nextDetectedGoodPtr = self.fp.tell()-len(chunk)+hit# Ptr to the beginning of the next header
		detectedFileFilesize = nextDetectedGoodPtr-lastGoodPtr-self.defaultFileHeaderLen
		
		# Now lastGoodPtr is the ptr to the right header, read the header and override the length in the header manually with detectedFileFilesize

		#self.fp.seek(lastGoodPtr)
		#currHeader = self.fp.read(self.defaultFileHeaderLen)

		return lastGoodPtr, detectedFileFilesize

		
		

	def R2D2(self, ptrHist, fileSize):


		prevOff = ptrHist[-1]
		originalHdrPtr = self.fp.tell()-self.defaultFileHeaderLen

		print ''# newline for progress meter
		print color.stdoutg("[~]")+" R2D2'ing"

		spinByteJumpPrev, spinByteJumpNext = (1024*1024*2, 1024*1024*2)
		previousHeaderLocation, nextHeaderLocation = 0,0


		#!#!# <!Code for finding previous hdr!>
		self.fp.seek(originalHdrPtr)
		while self.fp.tell()!=0:
			if self.fp.tell()<(spinByteJumpPrev*2):
				spinByteJumpPrev = self.fp.tell()
				chunk = self.fp.read(spinByteJumpPrev)
				hit = chunk.rfind('Decos Post tiff-file header')
				if hit>-1:
					# Previous header found
					print 'HIT FOUND'
					print chunk[hit:hit+199]
					previousHeaderLocation = hit+(self.fp.tell()-spinByteJumpPrev)
					break
			else:
				self.fp.seek(self.fp.tell()-spinByteJumpPrev)
				chunk = self.fp.read(spinByteJumpPrev)
				# Hit should be recorded here
				hit = chunk.rfind('Decos Post tiff-file header')
				if hit>-1:
					# Previous header found
					previousHeaderLocation = hit+(self.fp.tell()-spinByteJumpPrev)
					break
				self.fp.seek(self.fp.tell()-(spinByteJumpPrev*2))
		#!#!#
		#/#/# <!Code for finding next hdr!>
		self.fp.seek(originalHdrPtr)# Read from this header +1 so it won't hit on this header

		while self.fp.tell()!=fileSize:
			#if spinByteJumpNext<(fileSize-self.fp.tell()):
			#	spinByteJumpNext = fileSize-self.fp.tell()

			chunk = self.fp.read(spinByteJumpNext)

			hit = chunk.find('Decos Post tiff-file header')
			if hit>-1:
				nextHeaderLocation = self.fp.tell()-spinByteJumpNext+hit
				break
		#/#/#

		print 'R2D2 results'
		print previousHeaderLocation
		self.fp.seek(previousHeaderLocation)
		print repr(self.fp.read(100))
		print nextHeaderLocation
		self.fp.seek(nextHeaderLocation)
		print repr(self.fp.read(100))
		print 'Ptr history:'
		print ptrHist[-10:]
		print 'R2D2 EO results'

		self.fp.seek(originalHdrPtr)

		return previousHeaderLocation, nextHeaderLocation

	def decodeFileHeader(self, dscHdrConf, currHeader):
		# Decode the header properties; we use the global DSC header once found at the beginning of the file to determine the offsets
		# If you want speed, improve this function :)
		currHeaderConfig = {}
		for dscHdrKey in dscHdrConf:
			# Get current offset of bytes in header [start byte:end byte]
			currOffset = dscHdrConf[dscHdrKey]['len']

			# Get the offset propery
			prevOffset = 0
			#print 'Going in'
			#print dscHdrConf[dscHdrKey]['len']
			for n in range(0,dscHdrKey):
				#print 'Inside for n='+str(n)+' '+str(dscHdrConf[n])
				#print dscHdrConf[n]['len']
				
				currOffset+=dscHdrConf[n]['len']
			if dscHdrKey!=0:
				for n in range(0,dscHdrKey):
					prevOffset+=dscHdrConf[n]['len']
			currHeaderConfig[dscHdrConf[dscHdrKey]['description']] = currHeader[prevOffset:currOffset].strip()
		self.currHeaderConfig = currHeaderConfig
		return currHeaderConfig

	def writeAndGuessExtension(self, filepath, data):

		if self.deleteExisting==True:
			# If this file should be removed we have to find all files in the dir and rm everything that starts with this name
			fileInfo = self.hfs.getFileInfo(filepath)
			files = os.listdir(fileInfo['dir'])
			print ''
			print filepath
			print files
			for f in files:
				print f
				if f.find(fileInfo['fname'])>-1:
					os.system('rm "'+fileInfo['dir']+f+'"')
			#os.system('')
			#if self.deleteExisting==True:
			#	os.system('rm "'+filepath+'"')
			#else:

		if self.hfs.isFile(filepath):
			print color.stderr('[!] '+filepath+' already exists')
			sys.exit()


		fhw = open(filepath, 'w')
		fhw.write(data)
		fhw.close()
		
		extension = self.hfs.guessExtension(filepath)
		
		if extension=='':
			extension = '.txt'

		if self.hfs.isFile(filepath+extension):
			print color.stderr('[!] '+filepath+extension+' already exists (2)')
			sys.exit()


		os.rename(filepath, filepath+extension)
		
		
		return

	def prepareDumpLocation(self, args, seqNoUsed=False):#seqNoUsed can help for those cases where an old sequence number is editted


		# processed/{filename w/o extension}/{ID}/{Seq.No [_{0,1,2,3}]}/{Pagenumber}.{extension|tiff}
		# processed/IntFinla/IntFinla8677/1/00001.tif


		root = 'processed/'

		fileInfo = self.hfs.getFileInfo(self.dsc)
		fnameWoExt = fileInfo['fnameWoExt']+'/'

		# The ID is a readable string
		ID = args['currHeaderConfig']['ID'].replace('/','_')+'/'



		seqNo = args['currHeaderConfig']['Seq.number']

		# Add preceeding 0's for ABBYY
		pageNo = '%05d' % int(args['currHeaderConfig']['Pagenumber'])

		# make processed/{filename w/o extension}/
		if os.path.isdir(root+fnameWoExt)==False:
			os.mkdir(root+fnameWoExt)

		if os.path.isdir(root+fnameWoExt+ID)==False:
			os.mkdir(root+fnameWoExt+ID)


		# If this is the first file of the SeqNo check if it is being reused, if so it should add 1 number to the seqNoAdd
		if int(pageNo)==1:
			filez = os.listdir(root+fnameWoExt+ID)
			matchez = []
			for f in filez:
				isThisSeqNo = re.findall('^'+seqNo+'_(\d{1,3})$',f)
				if len(isThisSeqNo)==1:
					#matchez.append(isThisSeqNo[0])
					if os.path.isdir(root+fnameWoExt+ID+seqNo+'_'+isThisSeqNo[0])==True:
						seqNoUsed=True

		if seqNoUsed==False:
			# Always search the highest seqNo
			filez = os.listdir(root+fnameWoExt+ID)
			matchez = []
			for f in filez:
				isThisSeqNo = re.findall('^'+seqNo+'_(\d{1,3})$',f)
				if len(isThisSeqNo)==1:
					matchez.append(isThisSeqNo[0])
			highestReuseNo = 0
			if len(matchez)!=1:
				for match in matchez:
					if int(match)>int(highestReuseNo):
						highestReuseNo = match
			seqNoAdd = '_%s/' % highestReuseNo
		else:
			noTimesReused = 0
			while os.path.isdir(root+fnameWoExt+ID+seqNo+'_'+str(noTimesReused))==True:
				noTimesReused+=1
				if noTimesReused==1000:
					print color.stderr('[!!!] seqNo more than 1000 times reused - normally a seq.No is used 1-20 times')
					print root+fnameWoExt+ID+seqNo+'_'+str(noTimesReused)
					sys.exit()
			seqNoAdd = '_%s/' % noTimesReused
		### End of detemining the seqNoAdd

		if os.path.isdir(root+fnameWoExt+ID+seqNo+seqNoAdd)==False:
			os.mkdir(root+fnameWoExt+ID+seqNo+seqNoAdd)
		
		dscRoot = root+fnameWoExt
		fullfilepath = root+fnameWoExt+ID+seqNo+seqNoAdd+pageNo
		return dscRoot, fullfilepath


	def extractFileFromDsc(self, phase, tiffData='', args=''):# phase, currHeaderConfig, currSeqNo, dossierNo):

		

		# Construct the location where the extracted file will reside in; this is the filename stripped of it's extension
		fileInfo = self.hfs.getFileInfo(self.dsc)
		collectionRoot = 'processed/'+fileInfo['fnameWoExt']+'/'


		if phase=='setupdumpfolder':
			if os.path.isdir(collectionRoot)==False:
				os.mkdir(collectionRoot)
			return True
		elif phase=='dumpfile':
			#print 'Args> '
			#print args
			#print 'EoArgs'

			"""
			#> Configure the sequence number
			if args['currSeqNo']=="":
				args['currSeqNo']=args['currHeaderConfig']['Seq.number']
			#elif args['currHeaderConfig']['Seq.number']!=args['currSeqNo']:
			#	# What happened here? :O
			#	sys.exit()


			id_in_header = args['currHeaderConfig']['ID'].replace('/','_')
			
			dossierRoot = collectionRoot+id_in_header+args['currHeaderConfig']['Seq.number']+"/"
			if os.path.isdir(dossierRoot)==False:
				os.mkdir(dossierRoot)
				try:
					args['dircount']+=1
				except:
					args['dircount']=1

			files = os.listdir(dossierRoot)

			testDossierNo=-1
			for file in files:
				dummyDossierNo = int(re.findall("^\d+",file)[0])
				#print file
				#print "dummyDossierNo "+str(dummyDossierNo)
				#print "testDossierNo > "+str(testDossierNo)
				if dummyDossierNo>testDossierNo:
					testDossierNo=dummyDossierNo
			if testDossierNo==-1:
				dossierNo=0
			else:
				dossierNo=testDossierNo+1
			args['currSeqNo'] = args['currHeaderConfig']['Seq.number']
			
			if args['currHeaderConfig']['Pagenumber']=="1" and args['currHeaderConfig']['Seq.number']==args['currSeqNo']:
				dossierNo+=1
			#filename = ''
			filename = '%05d' % int(args['currHeaderConfig']['Pagenumber'])
			#filename+= '.tiff'

			fullfilepath = dossierRoot+str(dossierNo)+'/'+filename
			print fullfilepath

			try:
				currLen = int(args['currHeaderConfig']['Length'])
			except:
				return 1337# waddle back until it's fatal
			"""
			#prevOffset = self.fp.tell()
			#extractFileFromDump = self.fp.read(currLen)
			dscRoot, fullfilepath = self.prepareDumpLocation(args)
			self.dscRoot = dscRoot
			self.writeAndGuessExtension(fullfilepath, tiffData)


			"""
			if self.hfs.isFile(fullfilepath)==False:
				if len(tiffData)==0:
					print color.stderr('[!] Halp, tiffData does not contain anything')
					print args
					sys.exit()
				self.writeAndGuessExtension(fullfilepath, tiffData)
			else:
				print(color.stderr("[!] File "+fullfilepath+" already exists"))
				return 10
			#sys.exit()
			currHeaderConfig = self.currHeaderConfig
			print currHeaderConfig
			currSeqNo = args['currSeqNo']

			# Reset dossierNo here when Seq.number changes
			if currHeaderConfig['Seq.number'].replace(' ','')!=currSeqNo:
				#print "EXCEPTION LANDED AT BP1"
				print('OKAY THIS AIIINT RIGHT')
				sys.exit()
				if os.path.isdir(dossierRoot)==True:
					files = os.listdir(dossierRoot)
					testDossierNo=-1
						
					#print "PROGRESS OFFSET FROM BP1"
					for file in files:
						dummyDossierNo = int(re.findall("^\d+",file)[0])
						if dummyDossierNo>testDossierNo:
							testDossierNo=dummyDossierNo
							#print "EXCEPTION OCCURED!"
							#print dummyDossierNo
							#print files
							#print "CHANGED DOSSIER NO AUTO"
							
					if testDossierNo==-1:
				 		dossierNo=0
					else:
						dossierNo=testDossierNo+1
				else:
					dossierNo=0
					#print "PROCESS OFFSET OPTION 2 FROM BP1"
					
				
				currSeqNo=currHeaderConfig['Seq.number'].replace(" ","")

			if currHeaderConfig['Pagenumber'].replace(" ","")=="1" and currHeaderConfig['Seq.number'].replace(" ","")==currSeqNo:
				#print "EXCEPTION LANDED AT BP2"
				dossierNo+=1
		
			#saveResult('level1',{'srcFileOnDisk':srcFileOnDisk})# Pointless
			
			# Construct the filename
			#filename = ''
			#filename+= currHeaderConfig['Pagenumber'].replace(" ","")
			filename = '%05d' % int(currHeaderConfig['Pagenumber'].replace(" ",""))
			#filename+= ".tif"
			
			#fullfilepath = dossierRoot+str('%04d' % dossierNo)+"/"+filename.replace(' ','')
			fullfilepath = dossierRoot+str(dossierNo)+"/"+filename.replace(' ','')
			
			# Gather the content of the filie
			try:
				currLen = int(currHeaderConfig['Length'].replace(" ",""))
			except:
				return 8
			prevOffset = self.fp.tell()
			
			extractFileFromDump = tiffData
			
			if self.hfs.isFile(fullfilepath)==False:
				if os.path.isdir(dossierRoot+str(dossierNo))==False:
					#<<if os.path.isdir(dossierRoot+str('%04d' % dossierNo))==False:
					os.mkdir(dossierRoot+str(dossierNo))
					#os.mkdir(dossierRoot+str('%04d' % dossierNo))
					#dircount+=1
				if self.hfs.isFile(fullfilepath):
					# FATAL OUT
					return 9
				fhw = open(fullfilepath, 'w')
				fhw.write(extractFileFromDump)
				fhw.close()
			else:
				print(color.stderr("[!] File "+fullfilepath+" already exists"))
				return 10
			"""


	def checkCurrentFileInDsc(self):
		return 0

	def getHeaderCount(self):
		self.fp.seek(0)
		fc = self.fp.read()
		matches = re.findall('Decos Post tiff-file header',fc)
		return len(matches)-1#-1 because at the beginning of each DSC there is a header which describes the format of other headers, this header contains the same keyword



	def crawlFilesInDsc(self, action, globalHeaderLength, dscHdrConf, fileSize):

		prevOffset = globalHeaderLength
		currSeqNo = ''
		dossierNo = 0
		mode = 'check'#|extract
		filecounter = 0

		if action=='extract':
			self.extractFileFromDsc('setupdumpfolder')

		#self.DBG.dbg('dscHdrConf: '+repr(dscHdrConf),'crawlFilesInDsc')
		self.stats['hdrCnt'] = 0
		self.stats['filecounter'] = 0
		self.stats['bytecount'] = 0
		#self.stats['seqNos']

		print color.stdoutg("[+]")+" init decoding "+self.dsc
		#progressMeter = progress.ProgressMeter(total=fileSize)
		#progressMeter.update(self.fp.tell())
		ptrHist = []
		while self.fp.tell()!=fileSize:
			#print color.stdoutg('[+]')+' Cycling ~ FP is at '+str(self.fp.tell())+'/'+str(fileSize)+' previous was '+str(prevOffset)+' default file header len=>'+str(self.defaultFileHeaderLen)
			# Extract & analyse the current header
			ptrHist.append(self.fp.tell())
			currHeader = self.fp.read(self.defaultFileHeaderLen)
			#print currHeader

			ptr, detectedFilesize = 0,0# Always overwrite ptr here because then we can check the method's state
			self.deleteExisting = False# Whether to first delete the existing file

			if currHeader[0:5]!='Decos':# Check if this header is right
				ptr, detectedFilesize = self.R2D2_last_good_ptr_method(ptrHist, fileSize)
				if ptr!=0:
					# R2D2_last_good_ptr_method worked
					self.fp.seek(ptr)
					currHeader = self.fp.read(self.defaultFileHeaderLen)

					if currHeader[0:5]!='Decos':
						print 'NOHEADER'
						sys.exit()# This is pretty evil but hey
				else:


					prevHeaderLoc,nextHeaderLoc = self.R2D2(ptrHist, fileSize)

					#self.fp.seek(nextHeaderLoc)
					self.fp.seek(prevHeaderLoc)
					#print currHeader
					#print '[~] Dumping last 10 pointers'
					#print ptrHist[-10:]
	
					if nextHeaderLoc==1:
						return 6
					else:
						currHeader = self.fp.read(self.defaultFileHeaderLen)
						if currHeader[0:5]!='Decos':
							print color.stderr('[-] Error after R2D2')
							return 7
						#self.stats['filecounter'] += 1
					print currHeader
					#sys.exit()
			#print currHeader
			self.stats['hdrCnt'] +=1
			currHeaderConfig = self.decodeFileHeader(dscHdrConf, currHeader)

			if ptr!=0:# Override the current Length field if reqested
				currHeaderConfig['Length'] = str(detectedFilesize)
				# Allow the old file to be deleted and substracted from hdr count
				self.stats['hdrCnt'] -= 1# Maybe this should be 2; check IntGerma002.DSC
				self.deleteExisting = True

			#print currHeaderConfig

			try:
				currLen = int(currHeaderConfig['Length'])
			except:
				return 8

			# Have fun with the file
			self.stats['filecounter']+=1
			if action=='check':
				# While checking the DSC just shift the fp to the next header location
				self.fp.seek(self.fp.tell()+currLen)
				
			elif action=='extract':
				# In extraction mode we have to extract the current file
				tiffDataFromDsc = self.fp.read(currLen)

				self.extractFileFromDsc('dumpfile', tiffDataFromDsc, {
					'currHeaderConfig':	currHeaderConfig,
					'currSeqNo':	currSeqNo,
					'dossierNo':	dossierNo
				})
			prevOffset = self.fp.tell()
			#progressMeter.update(currLen)
			#sys.exit()
			#progressMeter.update(currLen+headerTotalLen)
		#progressMeter.update(fileSize)

		print(color.stdoutg("[+]")+" Ready decoding Decos dumpfile, calculating results")
		self.moveOn()
		return 0
	def moveOn(self):
		dirStats = self.hfs.getDirContentInfo(self.dscRoot, {'extension':{},'dirs':0,'files':0,'pdfPages':0,'bytes':0})
		amountOfHdrs = self.getHeaderCount()
		#self.stats['hdrCnt'] = amountOfHdrs
		#print(self.stats['filecounter'])
		
		#print(amountOfHdrs)
		print 'hdrCnt ('+str(self.stats['hdrCnt'])+') / regex hdr matches ('+str(amountOfHdrs)+') / amount of files in dir ('+str(dirStats['files'])+') '
		if int(self.stats['hdrCnt'])!=int(amountOfHdrs) or int(amountOfHdrs)!=int(dirStats['files']):
			print color.stderr('[!] Error found, moving to exceptions')
			self.qr.moveToExceptions(self.dsc, 'exceptions')
		else:
			print color.stdoutg('[+] Everything is fine, moving file')
			self.qr.moveToEvidence(self.dsc, 'evidence')
		#self.stats = stats
		#if mode=='check':
		#	print 'Check results:'
		#	print 'Filecount: '+str(filecounter)
		#	print 'Directory count: '+str(dircount)
