#!/usr/bin/python
import shutil
import sys,re,os,time,datetime,random

from utils.highFsInspector import HFS

from decimal import *

import goodies.progress
import goodies.color

#import ext_mysql

import pyPdf
class DSC_QR:
	settings = {
		'input':	'input/',
		'processed':	'processed/',
		'exceptions':	'exceptions/'
	}

	def __init__(self):
		self.hfs = HFS()

	def getPdfPageCount(self, fileName):
		return pyPdf.PdfFileReader(file(fileName, "r")).getNumPages()
	def getPdfPageCountFromDir(self, directory):
		print 'Counting PDF pages in: '+directory

		rec = True	
		currDirectory = directory
		pdfFiles = []
		if os.path.isdir(currDirectory):
			#print currDirectory
			listFiles = os.listdir(currDirectory)
			for f in listFiles:
				currDir = currDirectory+f
				if os.path.isdir(currDir):
					for herp in os.listdir(currDir):
						pdfFileDir = currDir+'/'+herp+'/'
						#print currDirr+'/'+herp
						for pdf in os.listdir(pdfFileDir):
							pdfFiles.append(pdfFileDir+pdf)
				#print listFiles
		pageCount = 0
		for pdf in pdfFiles:
			pageCount += self.getPdfPageCount(pdf)
		return pageCount


	### PROCEDURES
	def checkOcrConversion(self,pdfRoot):
		#self.crawlDSCHeader('check')

		fh = open('output.txt','r')
		c = fh.read()
		if c.find(self.dsc) != -1 or self.dsc.find('REDACTED') != -1:
			print 'THIS IS ALREADY SCANNED'
			fh.close()
			return 0
		fh.close()
		justTheFileName = re.findall('[^\/]+$', self.dsc)
		minusDSCExtension = justTheFileName[0][:-4]

		print minusDSCExtension
		derp = pdfRoot+minusDSCExtension+'/'

		pdfPageCount = self.getPdfPageCountFromDir(derp)
		self.crawlDSCHeader('check')

		
		# Top of output.txt should be "pdfP check	DSC check	Regex HdrCnt cnt	Location"
		#out = self.dsc+'; pdfP='+str(pdfPageCount)+'\tFC='+str(self.stats['filecounter'])+"\n"
		
		out = str(pdfPageCount)+"\t"+str(self.stats['filecounter'])+"\t"+str(self.stats['hdrCnt'])+"\t"+self.dsc+"\n"

		fh = open('output.txt','a')
		fh.write(out)
		fh.close()
	def procSuccess(self):
		root = '/media/PCAPS/scans/'
		pdf_root = '/media/PCAPS/DecosUpload/upload11-6-2012/'

		processedDir = "/media/PCAPS/processed/folders/"
		DSCevidenceDir = "/media/PCAPS/processed/dscs/"

		fh = open("output.txt","r")
		fh.readline()
		contents = fh.read()
		for line in contents.split("\n"):
			if line == '':
				print 'empty newline found'
			else:
				details = line.split('\t')
				print details

				if len(details) < 4:
					#print details
					sys.exit()
				if details[0] == details[1] == details[2]:
					currentDSC = details[3]
					justTheFileName = re.findall('[^\/]+$', currentDSC)
					minusDSCExtension = justTheFileName[0][:-4]
					srcLoc = pdf_root+minusDSCExtension+'/'
					print currentDSC+' => '+DSCevidenceDir
					os.system('cp -r "'+currentDSC+'" "'+DSCevidenceDir+'"')
					print srcLoc+' => '+processedDir
					os.system('cp -r "'+srcLoc+'" "'+processedDir+'"')
					print '=*=*=*=*=*=*=*=*='
					print currentDSC+' processed'
					fh = open('processed.txt','a')
					fh.write(currentDSC+'\n')
					fh.close()
	def moveToEvidence(self, dsc, evidenceDir):
		print '%s => %s' % (dsc, evidenceDir)
		os.system('cp -r "%s" "%s"' % (dsc, evidenceDir))
		os.system('rm "%s"' % dsc)
	def moveToExceptions(self, dsc, exceptionDir):
		print '%s => %s' % (dsc, exceptionDir)
		os.system('cp -r "%s" "%s"' % (dsc, exceptionDir))
		os.system('rm "%s"' % dsc)
	def rmExceptionResults(self, exceptionDir='exceptions', processedDir='processed'):
		exceptions = os.listdir(exceptionDir)
		for exception in exceptions:
			fileInfo = self.hfs.getFileInfo(exceptionDir+'/'+exception)
			processedLoc = processedDir+'/'+fileInfo['fnameWoExt']
			print 'Removing %s' % processedLoc
			os.system('rm -rf "%s"' % processedLoc)
	def procExceptions(self):
		root = '/media/PCAPS/scans/'
		pdf_root = '/media/PCAPS/DecosUpload/upload11-6-2012/'

		processedDir = "/media/PCAPS/processed/folders/"
		DSCevidenceDir = "/media/PCAPS/processed/dscs/"
		DSCExceptionsDir = "/media/PCAPS/processed/exceptions/"
		fh = open("_processed.txt","r")
		contents = fh.read()
		filez = os.listdir(root)
		#print filez
		notprocessed = 0
		processed = 0
		for f in filez:
			match = re.findall(f, contents)
			if len(match) > 0:
				print f+' has been processed'
				processed+=1
			else:
				ext = f[-4:]
				if ext == '.DSC':
					print 'DSC is not processed yet'
					notprocessed+=1
		print 'Not processed	'+str(notprocessed)
		print 'Processed	'+str(processed)
		print '------------+'
		print 'Total		'+str(notprocessed+processed)

		fh = open("output.txt")
		contents = fh.read()

		for line in contents.split("\n"):
			if line == '':
				print 'empty newline found'
			else:
				details = line.split('\t')
				#print details
				if len(details) < 4:
					#print details
					print "LESS THAN 4"
					sys.exit()
				if details[0] == details[1] == details[2]:
					print "OK"
					"""
					currentDSC = details[3]
					justTheFileName = re.findall('[^\/]+$', currentDSC)
					minusDSCExtension = justTheFileName[0][:-4]
					srcLoc = pdf_root+minusDSCExtension+'/'
					print currentDSC+' => '+DSCevidenceDir
					os.system('cp -r "'+currentDSC+'" "'+DSCevidenceDir+'"')
					print srcLoc+' => '+processedDir
					os.system('cp -r "'+srcLoc+'" "'+processedDir+'"')
					print '=*=*=*=*=*=*=*=*='
					print currentDSC+' processed'
					fh = open('processed.txt','a')
					fh.write(currentDSC+'\n')
					fh.close()
					"""
				else:
					print "EXCEPTION"
					currentDSC = details[3]
					print currentDSC+" was not properly processed"

					currentDSC = details[3]
					justTheFileName = re.findall('[^\/]+$', currentDSC)
					minusDSCExtension = justTheFileName[0][:-4]
					srcLoc = pdf_root+minusDSCExtension+'/'
					print currentDSC+' => '+DSCevidenceDir
					#os.system('cp -r "'+currentDSC+'" "'+DSCExceptionsDir+'"')
					print srcLoc+' => '+processedDir
					#os.system('cp -r "'+srcLoc+'" "'+processedDir+'"')
					print '=*=*=*=*=*=*=*=*='
					print currentDSC+' processed'
					#fh = open('processed.txt','a')
					#fh.write(currentDSC+'\n')
					#fh.close()
		#sys.exit()
		# /media/PCAPS/DecosUpload/upload11-6-2012/|REDACTED|/
		
		#print pdfRoot+self.dsc[:-4]
		
		# /media/PCAPS/DecosUpload/upload11-6-2012/|REDACTED|/
	
	def unknown_procedure_1():
		files = os.listdir('/media/PCAPS/all-dscs/')
		dscC = 0
		for f in files:
			R001DscFolder = '/media/PCAPS/dscs-R001/extracted-ocred-ready/'+f.replace('.DSC','')
			if os.path.isdir(R001DscFolder) == True:
				print os.system('rm "/media/PCAPS/all-dscs/'+f+'"')
			else:
				print f+' todo'
			dscName = '/media/PCAPS/all-dscs/'+f
			dscC+=1
		print dscC

	def unknown_procedure_2():
		d = DSC()
		d.procExceptions()
		sys.exit()
		#dsc_inst = DSC('../../../dscs/|REDACTED|.DSC')
		#dsc_inst = DSC(sys.argv[1])



		#d = DSC(sys.argv[1])
		#d.crawlDSCHeader('check')
	def unknown_procedure_3():
		root = '/media/PCAPS/scans/'
		pdf_root = '/media/PCAPS/DecosUpload/upload11-6-2012/'



		sys.exit()
		ls = os.listdir(root)
		#print ls
		for f in ls:
			ext = f[-4::]
			if ext == '.DSC' or ext=='.dsc':
				#pass
				print '[~] check -> '+f
				d = DSC(root+f)
				#d.crawlDSCHeader('check')
		
				d.checkOcrConversion(pdf_root)		
			else:
				print '[-] Not DSC: '+f

		#	print(f)
		#	d = DSC('/home/system/.gvfs/r on 192.168.11.10/EVIDENCE/20111004_Decos/scans/'+f)
		#	d.crawlDSCHeader('check')

		#print dsc_inst.dsc
		#print repr(dsc_inst.isDSC())
		#print dsc_inst.crawlDSCHeader('check')
