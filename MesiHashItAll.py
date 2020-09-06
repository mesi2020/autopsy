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

#import hashlib

import jarray
import inspect
from java.lang import System
from java.util.logging import Level
from javax.swing import JCheckBox
from javax.swing import BoxLayout
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import GenericIngestModuleJobSettings
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import IngestModuleGlobalSettingsPanel
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.autopsy.coreutils import Logger
from java.lang import IllegalArgumentException



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

from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import GenericIngestModuleJobSettings

from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.casemodule.services import Blackboard
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from mailbox import _PartialFile
import _hashlib
from __builtin__ import str

# Imports GUI related
from java.awt import Panel, BorderLayout, EventQueue, GridLayout, GridBagLayout, GridBagConstraints, Font, Color      
from java.awt.event import ActionListener, ActionEvent 
from javax.swing import JFrame, JLabel, JButton, JTextField, JComboBox, JTextField, JProgressBar, JMenuBar, JMenuItem, JTabbedPane, JPasswordField, JCheckBox, SwingConstants, BoxLayout, JPanel
from javax.swing.border import TitledBorder, EtchedBorder, EmptyBorder



# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the anlaysis.
# TODO: Rename this to something more specific.  Search and replace for it because it is used a few times
# TODO: 1) Substituir o nome do modulo
class MesiHash(IngestModuleFactoryAdapter):
    def __init__(self):
        self.settings = None
        
    moduleName = "Mesi: Multi Digest Hash"

    def getModuleDisplayName(self):
        return self.moduleName

    # TODO: Give it a description
    def getModuleDescription(self):
        return "Hash with md5, sha1, sha256, sha384, sha512"

    def getModuleVersionNumber(self):
        return "0.5"

    # Return true if module wants to get called for each file
    def isFileIngestModuleFactory(self):
        return True
    
    # Settings and GUI panel
    def getDefaultIngestJobSettings(self):
        return GenericIngestModuleJobSettings()

    def hasIngestJobSettingsPanel(self):
        return True
    
    def getIngestJobSettingsPanel(self, settings):
        #if not isinstance(settings, GenericIngestModuleJobSettings):
        #    raise IllegalArgumentException("Expected settings argument to be instanceof GenericIngestModuleJobSettings")
        self.settings = settings
        return MesiPanel(self.settings)
        #pass
    # TODO: Update class name to one that you create below
    # can return null if isFileIngestModuleFactory returns false
    
    def createFileIngestModule(self, ingestOptions):
        return MesiHashFileIngestModule(self.settings)


# File-level ingest module.  One gets created per thread.
# TODO: Rename this to something more specific. Could just remove "Factory" from above name.
# Looks at the attributes of the passed in file.
class MesiHashFileIngestModule(FileIngestModule):

    # Autopsy will pass in the settings from the UI panel
    def __init__(self, settings):
        self.local_settings = settings

    _logger = Logger.getLogger(MesiHash.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

        
    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/4.6.0/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    # TODO: Add any setup code that you need here.
        
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
            sha256_hash = ""
            sha384_hash = ""
            sha512_hash = ""
               
            try:
                        
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
                            
               
                try:
                    inputStream = ReadContentInputStream(file)            
                    md5_hash = DigestUtils.md5Hex(inputStream)
                    self.log(Level.INFO, "md5Hex")
                except Exception as e:
                    md5_hash=""
                    self.log(Level.SEVERE, "Erro a calcular md5Hex")
               
                try: 
                    inputStream = ReadContentInputStream(file)                                 
                    sha1_hash = DigestUtils.sha1Hex(inputStream)
                    self.log(Level.INFO, "sha1Hex")
                except Exception as e:
                    sha1_hash=""
                    self.log(Level.SEVERE, "Erro a calcular sha1Hex")
               
               
            
               
            except Exception as e:
                self.log(Level.SEVERE, "Erro a ler o ficheiro")


            #Para cada ficheiro adiciona um artefato
            
            art = file.newArtifact(artID)            
            art.addAttribute(BlackboardAttribute(attIdmd5, MesiHash.moduleName, md5_hash))         
            art.addAttribute(BlackboardAttribute(attIdsha1, MesiHash.moduleName, sha1_hash))     
            art.addAttribute(BlackboardAttribute(attIdsha256, MesiHash.moduleName, sha256_hash))
            art.addAttribute(BlackboardAttribute(attIdsha384, MesiHash.moduleName, sha384_hash))
            art.addAttribute(BlackboardAttribute(attIdsha512, MesiHash.moduleName, sha512_hash))
            blackboard.indexArtifact(art)
            
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


#Settings GUI

class MesiPanel(IngestModuleIngestJobSettingsPanel):
    # Note, we can't use a self.settings instance variable.
    # Rather, self.local_settings is used.
    # https://wiki.python.org/jython/UserGuide#javabean-properties
    # Jython Introspector generates a property - 'settings' on the basis
    # of getSettings() defined in this class. Since only getter function
    # is present, it creates a read-only 'settings' property. This auto-
    # generated read-only property overshadows the instance-variable -
    # 'settings'

    # We get passed in a previous version of the settings so that we can
    # prepopulate the UI
    # TODO: Update this for your UI
    def __init__(self, settings):
        self.local_settings = settings
        self.initComponents()
        self.customizeComponents()

    # TODO: Update this for your UI
    def checkBoxEvent(self, event):
        if self.checkbox.isSelected():
            self.local_settings.setSetting("flag", "true")
        else:
            self.local_settings.setSetting("flag", "false")

    # TODO: Update this for your UI
    def initComponents(self):
        
        
        self.setLayout(None)
        
        lblNewLabel_2 = JLabel("May take a while... Please be patient")
        lblNewLabel_2.setHorizontalAlignment(SwingConstants.LEFT)
        lblNewLabel_2.setFont(Font("Tahoma", Font.BOLD, 14))
        lblNewLabel_2.setBackground(Color.YELLOW)
        lblNewLabel_2.setBounds(10, 227, 347, 23)
        self.add(lblNewLabel_2)
        
        lblNewLabel_1 = JLabel("Select only the necessariy Algorithms")
        lblNewLabel_1.setFont(Font("Tahoma", Font.BOLD | Font.ITALIC, 11))
        lblNewLabel_1.setHorizontalAlignment(SwingConstants.LEFT)
        lblNewLabel_1.setBounds(10, 33, 243, 14)
        self.add(lblNewLabel_1);
        
        cTAGGED_FILES = JCheckBox("PROCESS ONLY TAGGED FILES")
        cTAGGED_FILES.setSelected(True)
        cTAGGED_FILES.setBounds(10, 202, 193, 23)
        self.add(cTAGGED_FILES)
        
        panel = JPanel(None)
        panel.setLayout(None)
        panel.setBorder(TitledBorder(EtchedBorder(EtchedBorder.LOWERED, Color(255, 255, 255), Color(160, 160, 160)), "Digest Algorithms", TitledBorder.LEADING, TitledBorder.TOP, None, Color(0, 0, 0)))
        panel.setBounds(10, 56, 222, 139)
        self.add(panel)
        
        cMD5 = JCheckBox("MD5 - RFC 1321")
        cMD5.setBounds(6, 16, 147, 23)
        panel.add(cMD5)
        
        cSHA1 = JCheckBox("SHA1 - FIPS PUB 180-2")
        cSHA1.setBounds(6, 39, 180, 23);
        panel.add(cSHA1)
        
        cSHA256 = JCheckBox("SHA256 - FIPS PUB 180-2")
        cSHA256.setBounds(6, 62, 180, 23)
        panel.add(cSHA256)
        
        cSHA384 = JCheckBox("SHA384 - FIPS PUB 180-2")
        cSHA384.setBounds(6, 86, 180, 23)
        panel.add(cSHA384)
        
        cSHA512 = JCheckBox("SHA512 - FIPS PUB 180-2")
        cSHA512.setBounds(6, 109, 180, 23)
        panel.add(cSHA512)
        
        lblWarningHashCalculation = JLabel("Warning: Hash calculation is time consuming. ")
        lblWarningHashCalculation.setBounds(10, 5, 416, 23)
        self.add(lblWarningHashCalculation)
        lblWarningHashCalculation.setHorizontalAlignment(SwingConstants.LEFT)
        
        lblNewLabel = JLabel("GPL 3.0 Source: https://github.com/mesi2020/autopsy")
        lblNewLabel.setBounds(10, 281, 317, 14)
        self.add(lblNewLabel)
#         

    # TODO: Update this for your UI
    def customizeComponents(self):
        try:
            self.checkbox.setSelected(self.local_settings.getSetting("flag") == "true")
        except:
            pass
        

    # Return the settings used
    def getSettings(self):
        return self.local_settings
