from six.moves import input
methname = input("Method name: ")
attrname = input("Attr name: ")
attrtype = input("Attr type: ")


o = open("Output.txt","a") 
for line in open("TemplateNpingOps.txt"):
   line = line.replace("ATTRNAME",attrname)
   line = line.replace("METHNAME",methname)
   line = line.replace("TYPE",attrtype)
   o.write(line) 
o.close()
