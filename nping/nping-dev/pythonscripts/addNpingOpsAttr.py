methname = raw_input("Method name: ")
attrname = raw_input("Attr name: ")
attrtype = raw_input("Attr type: ")


o = open("Output.txt","a") 
for line in open("TemplateNpingOps.txt"):
   line = line.replace("ATTRNAME",attrname)
   line = line.replace("METHNAME",methname)
   line = line.replace("TYPE",attrtype)
   o.write(line) 
o.close()
