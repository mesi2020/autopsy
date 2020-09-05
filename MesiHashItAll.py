# https://www.python.org/dev/peps/pep-0263/

# Sample module in the public domain. Feel free to use this as a template
# for your modules (and you can remove this header and take complete credit
# and liability)
#
# Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
#
# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

# Simple file-level ingest module for Autopsy.
# Search for TODO for the things that you need to change
# See http://sleuthkit.org/autopsy/docs/api-docs/4.6.0/index.html for documentation

import hashlib
from org.apache.commons.codec.digest import DigestUtils
import jarray
import inspect
from java.lang import System
from java.util.logging import Level
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.casemodule.services import Blackboard
from mailbox import _PartialFile
import _hashlib
from __builtin__ import str

# Imports GUI related
from java.awt import Panel, BorderLayout, EventQueue, GridLayout, GridBagLayout, GridBagConstraints      
from java.awt.event import ActionListener, ActionEvent 
from javax.swing import JFrame, JLabel, JButton, JTextField, JComboBox, JTextField, JProgressBar, JMenuBar, JMenuItem, JTabbedPane, JPasswordField, JCheckBox, SwingConstants
from javax.swing.border import TitledBorder
from javax.swing.border import EmptyBorder  


# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the anlaysis.
# TODO: Rename this to something more specific.  Search and replace for it because it is used a few times
# TODO: 1) Substituir o nome do modulo
class MesiHash(IngestModuleFactoryAdapter):

    # TODO: give it a unique name.  Will be shown in module list, logs, etc.
    moduleName = "Mesi Hash It All"

    def getModuleDisplayName(self):
        return self.moduleName

    # TODO: Give it a description
    def getModuleDescription(self):
        return "Hash with md5, sha1, sha224, sha256, sha384, sha512"

    def getModuleVersionNumber(self):
        return "0.1"

    # Return true if module wants to get called for each file
    def isFileIngestModuleFactory(self):
        return True

    # can return null if isFileIngestModuleFactory returns false
    def createFileIngestModule(self, ingestOptions):
        return MesiHashFileIngestModule()


# File-level ingest module.  One gets created per thread.
# TODO: Rename this to something more specific. Could just remove "Factory" from above name.
# Looks at the attributes of the passed in file.
class MesiHashFileIngestModule(FileIngestModule):

    _logger = Logger.getLogger(MesiHash.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/4.6.0/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    # TODO: Add any setup code that you need here.
    def addNumbers(self, event):
        print "add"
        ttl = int(self.txt1.getText()) + int(self.txt2.getText())
        self.txt3.setText(str(ttl))
        
    def guiTest(self):
        frame = JFrame("Painel de configuracao")        
        self.log(Level.INFO, "DEBUG: Criei uma frame")
        #frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE)
        #frame.setLocation(100,100)
        frame.setSize(1024,768)
        frame.setLayout(None)

        lbl1 = JLabel("Phy")
        lbl1.setBounds(60,20,40,20)
        self.txt1 = JTextField(10)
        self.txt1.setBounds(120,20,60,20)
        lbl2 = JLabel("Maths")
        lbl2.setBounds(60,50,40,20)
        self.txt2 = JTextField(10)
        self.txt2.setBounds(120, 50, 60,20)
        btn = JButton("Add", actionPerformed = self.addNumbers)
        btn.setBounds(60,80,60,20)
        lbl3 = JLabel("Total")
        lbl3.setBounds(60,110,40,20)
        self.txt3 = JTextField(10)
        self.txt3.setBounds(120, 110, 60,20)
        frame.add(lbl1)
        frame.add(self.txt1)
        frame.add(lbl2)
        frame.add(self.txt2)
        frame.add(btn)
        frame.add(lbl3)
        frame.add(self.txt3)

        frame.setVisible(True)
        self.log(Level.INFO, "DEBUG: Ate aqui tudo bem")
        
    def startUp(self, context):
        self.filesFound = 0

        self.log(Level.INFO, "DEBUG: iniciei")
        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException("Oh No!")
        #        
        pass

    # Where the analysis is done.  Each file will be passed into here.
    # The 'file' object being passed in is of type org.sleuthkit.datamodel.AbstractFile.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/4.6.0/classorg_1_1sleuthkit_1_1datamodel_1_1_abstract_file.html
    # TODO: Add your analysis code in here.
    def process(self, file):
        # Skip non-files
        skCase = Case.getCurrentCase().getSleuthkitCase();
        
        sha256_hash = hashlib.sha256()
                
        if ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS) or
            (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS) or
            (file.isFile() == False)):
            return IngestModule.ProcessResult.OK

        # Use blackboard class to index blackboard artifacts for keyword search
        blackboard = Case.getCurrentCase().getServices().getBlackboard()
        
        # For an example, we will flag files with .txt in the name and make a blackboard artifact.
        if (1==1):
            
            self.log(Level.INFO, "Encontrei um ficheiro " + file.getName())
            self.filesFound+=1

            # Make an artifact on the blackboard.  TSK_INTERESTING_FILE_HIT is a generic type of
            # artifact.  Refer to the developer docs for other examples.
            
            # Setup Artifact and Attributes - Teste

            #######################
            try:
                #self.log(Level.INFO, "Begin Create New Artifacts")
                artID = skCase.addArtifactType( "TSK_MESIHASH", "MESI:Calculated Files Hash")
            except:		
                #self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")
                pass
        
            # Criacao de um atributo MD5 do tipo string
            try:
                attIdmd5 = skCase.addArtifactAttributeType("TSK_FILE_MESIMD5", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "MD5")
            except:
                attIdmd5 = skCase.getAttributeType("TSK_FILE_MESIMD5")		
                #self.log(Level.INFO, "Attributes Creation Error, TSK_FILE_MESIMD5 ==> ")
                
            # Criacao de um atributo do SHA1 tipo string
            try:
                attIdsha1 = skCase.addArtifactAttributeType("TSK_FILE_MESISHA1", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "SHA1")
            except:
                attIdsha1 = skCase.getAttributeType("TSK_FILE_MESISHA1")		
                #self.log(Level.INFO, "Attributes Creation Error, TSK_FILE_MESISHA1 ==> ")
                
            # Criacao de um atributo do SHA224 tipo string
            #try:
            #    attIdsha224 = skCase.addArtifactAttributeType("TSK_FILE_MESISHA224", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "SHA224")
            #except:
            #    attIdsha224 = skCase.getAttributeType("TSK_FILE_MESISHA224")		
                #self.log(Level.INFO, "Attributes Creation Error, TSK_FILE_MESISHA224 ==> ")
                
            # Criacao de um atributo do SHA256 tipo string
            try:
                attIdsha256 = skCase.addArtifactAttributeType("TSK_FILE_MESISHA256", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "SHA256")
            except:
                attIdsha256 = skCase.getAttributeType("TSK_FILE_MESISHA256")		
                #self.log(Level.INFO, "Attributes Creation Error, TSK_FILE_MESISHA256 ==> ")
                
            # Criacao de um atributo do SHA256 tipo string
            try:
                attIdsha384 = skCase.addArtifactAttributeType("TSK_FILE_MESISHA384", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "SHA384")
            except:
                attIdsha384 = skCase.getAttributeType("TSK_FILE_MESISHA384")		
                #self.log(Level.INFO, "Attributes Creation Error, TSK_FILE_MESISHA384 ==> ")
            
            # Criacao de um atributo do SHA512 tipo string
            try:
                attIdsha512 = skCase.addArtifactAttributeType("TSK_FILE_MESISHA512", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "SHA512")
            except:
                attIdsha512 = skCase.getAttributeType("TSK_FILE_MESISHA512")		
                #self.log(Level.INFO, "Attributes Creation Error, TSK_FILE_MESISHA512 ==> ")
                
            #Obtem o artefacto, por nome
            artID = skCase.getArtifactTypeID("TSK_MESIHASH")
            md5_hash = ""
            sha1_hash = ""
            sha224_hash = ""
            sha256_hash = ""
            sha384_hash = ""
            sha512_hash = ""
               
            try:
               # Processamento - Calculo do sha256
               #sha256_hash = hashlib.sha256()
               # Processamento - Calculo do sha1
               #sha1_hash = hashlib.sha1()
               # Processamento - Calculo do sha224
               #sha224_hash = hashlib.sha224()
               # Processamento - Calculo do sha384
               #sha384_hash = hashlib.sha384()
               # Processamento - Calculo do sha512
               #sha512_hash = hashlib.sha512()
               # Processamento - Calculo do md5
               #md5_hash = hashlib.md5()
                        
               try:
                  inputStream = ReadContentInputStream(file)
                  sha512_hash = DigestUtils.sha512Hex(inputStream)
                  self.log(Level.INFO, "sha512Hex")
               except Exception as e:
                   sha512_hash=""
                   self.log(Level.SEVERE, "Erro a calcular sha512Hex")

               try:
                  inputStream = ReadContentInputStream(file)
                  sha256_hash = DigestUtils.sha256Hex(inputStream)
                  self.log(Level.INFO, "sha256Hex")
               except Exception as e:
                   sha256_hash=""
                   self.log(Level.SEVERE, "Erro a calcular sha256Hex")
               
               try:
                   inputStream = ReadContentInputStream(file)
                   sha384_hash = DigestUtils.sha384Hex(inputStream)
                   self.log(Level.INFO, "sha384Hex")
               except Exception as e:
                   sha384_hash=""
                   self.log(Level.SEVERE, "Erro a calcular sha384Hex")
               
               #try:
               #    inputStream = ReadContentInputStream(file)   
               #    sha224_hash = DigestUtils.sha224Hex(inputStream)
               #    self.log(Level.INFO, "sha224Hex")
               #except Exception as e:
               #    sha224_hash=""
               #    self.log(Level.SEVERE, "Erro a calcular sha224Hex")
               
               try:
                   inputStream = ReadContentInputStream(file)            
                   md5_hash = DigestUtils.md5Hex(inputStream)
                   self.log(Level.INFO, "md5Hex")
               except Exception as e:
                   shamd5_hash=""
                   self.log(Level.SEVERE, "Erro a calcular md5Hex")
               
               try: 
                   inputStream = ReadContentInputStream(file)                                 
                   sha1_hash = DigestUtils.sha1Hex(inputStream)
                   self.log(Level.INFO, "sha1Hex")
               except Exception as e:
                   sha1_hash=""
                   self.log(Level.SEVERE, "Erro a calcular sha1Hex")
               
               
            
               #buffer = jarray.zeros(4096, "b")
               #totLen = 0
            
               #len = inputStream.read(buffer)
               #sha256_hash.update(buffer)
               #sha1_hash.update(buffer)
               #sha224_hash.update(buffer)
               #sha384_hash.update(buffer)
               #sha512_hash.update(buffer)
               #md5_hash.update(buffer)
            
               #while (len != -1):
               #   totLen = totLen + len                    
               #   len = inputStream.read(buffer)                    
               #   sha256_hash.update(buffer)
               #   sha224_hash.update(buffer)
               #   sha384_hash.update(buffer)
               #   sha512_hash.update(buffer)
               #   sha1_hash.update(buffer)
                  #md5_hash.update(buffer)
               
            except Exception as e:
               self.log(Level.SEVERE, "Erro a ler o ficheiro")


            #Para cada ficheiro adiciona um artefato
            #try:
            art = file.newArtifact(artID)            
            art.addAttribute(BlackboardAttribute(attIdmd5, MesiHash.moduleName, md5_hash))         
            art.addAttribute(BlackboardAttribute(attIdsha1, MesiHash.moduleName, sha1_hash))     
            #art.addAttribute(BlackboardAttribute(attIdsha224, MesiHash.moduleName, sha224_hash))            
            art.addAttribute(BlackboardAttribute(attIdsha256, MesiHash.moduleName, sha256_hash))
            art.addAttribute(BlackboardAttribute(attIdsha384, MesiHash.moduleName, sha384_hash))
            art.addAttribute(BlackboardAttribute(attIdsha512, MesiHash.moduleName, sha512_hash))
            blackboard.indexArtifact(art)
            #except Exception as e:
            #   self.log(Level.SEVERE, "Error indexing artifact ")

                          
            
            try:
               IngestServices.getInstance().fireModuleDataEvent(
                   ModuleDataEvent(MesiHash.moduleName,
                      BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_ARTIFACT_HIT, None))
            except Exception as e:
               self.log(Level.SEVERE, "Erro ao disparar o evento")
            
        return IngestModule.ProcessResult.OK

    # Where any shutdown code is run and resources are freed.
    # TODO: Add any shutdown code that you need here.
    def shutDown(self):
        # As a final part of this example, we'll send a message to the ingest inbox with the number of files found (in this thread)
        message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA, MesiHash.moduleName,
                str(self.filesFound) + " files found")
        ingestServices = IngestServices.getInstance().postMessage(message)