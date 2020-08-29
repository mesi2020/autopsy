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
from javax.swing import JFrame, JLabel, JButton, JTextField

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
        

    def startUp(self, context):
        self.filesFound = 0

        self.log(Level.INFO, "DEBUG: iniciei")
        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException("Oh No!")
        #
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
        if file.getName().lower().endswith(".txt"):
            
            self.log(Level.INFO, "Encontrei um ficheiro de texto: " + file.getName())
            self.filesFound+=1

            # Make an artifact on the blackboard.  TSK_INTERESTING_FILE_HIT is a generic type of
            # artifact.  Refer to the developer docs for other examples.
            
            # Setup Artifact and Attributes - Teste

            #######################
            try:
                self.log(Level.INFO, "Begin Create New Artifacts")
                artID_ls = skCase.addArtifactType( "TSK_MESIHASH", "MESI:Calculated Files Hash")
            except:		
                self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")
        
            # Criacao de um atributo MD5 do tipo string
            try:
                attIdmd5 = skCase.addArtifactAttributeType("TSK_FILE_MESIMD5", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "MD5")
            except:
                attIdmd5 = skCase.getAttributeType("TSK_FILE_MESIMD5")		
                self.log(Level.INFO, "Attributes Creation Error, TSK_FILE_MESIMD5 ==> ")
                
            # Criacao de um atributo do SHA1 tipo string
            try:
                attIdsha1 = skCase.addArtifactAttributeType("TSK_FILE_MESISHA1", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "SHA1")
            except:
                attIdsha1 = skCase.getAttributeType("TSK_FILE_MESIMD5")		
                self.log(Level.INFO, "Attributes Creation Error, TSK_FILE_MESISHA1 ==> ")
                
            # Criacao de um atributo do SHA256 tipo string
            try:
                attIdsha256 = skCase.addArtifactAttributeType("TSK_FILE_MESISHA256", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "SHA256")
            except:
                attIdsha256 = skCase.getAttributeType("TSK_FILE_MESI256")		
                self.log(Level.INFO, "Attributes Creation Error, TSK_FILE_MESI256 ==> ")
            
            # Criacao de um atributo do SHA512 tipo string
            try:
                attIdsha512 = skCase.addArtifactAttributeType("TSK_FILE_MESISHA512", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "SHA512")
            except:
                attIdsha512 = skCase.getAttributeType("TSK_FILE_MESI512")		
                self.log(Level.INFO, "Attributes Creation Error, TSK_FILE_MESI512 ==> ")
                

            artifactName = "TSK_MESIHASH"
            artId = skCase.getArtifactTypeID(artifactName)
            
            ######################
            
            art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)                     
            att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME,
                                      MesiHash.moduleName, "Ficheiros Hash")
                                      
                                                 
            art.addAttribute(att)

            try:
                # index the artifact for keyword search
                blackboard.indexArtifact(art)
            except Blackboard.BlackboardException as e:
                self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())
                
            #Para cada ficheiro adiciona um artefato
            art = file.newArtifact(artId)            
            art.addAttribute(BlackboardAttribute(attIdmd5, MesiHash.moduleName, "jhasdi76asdkgasdjyt76ads"))         
            art.addAttribute(BlackboardAttribute(attIdsha1, MesiHash.moduleName, "asfdsassdi76asdkgasdjyt76ads"))         
            art.addAttribute(BlackboardAttribute(attIdsha256, MesiHash.moduleName, "gfgasfdsassdi76asdkgasdjyt76ads"))
            art.addAttribute(BlackboardAttribute(attIdsha512, MesiHash.moduleName, "asfdsassdi76asdkgasdjyt76ads"))

            #adiciona o artefato no blackboard
            try:
                # index the artifact for keyword search
                blackboard.indexArtifact(art)
            except Blackboard.BlackboardException as e:
                self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())
            IngestServices.getInstance().fireModuleDataEvent(
                ModuleDataEvent(MesiHash.moduleName,
                    BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_ARTIFACT_HIT, None))

            # Fire an event to notify the UI and others that there is a new artifact
            IngestServices.getInstance().fireModuleDataEvent(
                ModuleDataEvent(MesiHash.moduleName,
                                BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT, None))


            # For the example (this wouldn't be needed normally), we'll query the blackboard for data that was added
            # by other modules. We then iterate over its attributes.  We'll just print them, but you would probably
            # want to do something with them.
            artifactList = file.getArtifacts(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
            for artifact in artifactList:
                attributeList = artifact.getAttributes()
                for attrib in attributeList:
                    self.log(Level.INFO, attrib.toString())

            # To further the example, this code will read the contents of the file and count the number of bytes
            inputStream = ReadContentInputStream(file)
            buffer = jarray.zeros(1024, "b")
            totLen = 0
            len = inputStream.read(buffer)
            while (len != -1):
                    totLen = totLen + len
                    len = inputStream.read(buffer)                    

        return IngestModule.ProcessResult.OK

    # Where any shutdown code is run and resources are freed.
    # TODO: Add any shutdown code that you need here.
    def shutDown(self):
        # As a final part of this example, we'll send a message to the ingest inbox with the number of files found (in this thread)
        message = IngestMessage.createMessage(
            IngestMessage.MessageType.DATA, MesiHash.moduleName,
                str(self.filesFound) + " files found")
        ingestServices = IngestServices.getInstance().postMessage(message)