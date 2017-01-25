from builtins import input
methname = eval(input("Method name: "))
attrname = eval(input("Attr name: "))
attrtype = eval(input("Attr type: "))


o = open("Output.txt","a") 
for line in open("TemplateNpingOps.txt"):
   line = line.replace("ATTRNAME",attrname)
   line = line.replace("METHNAME",methname)
   line = line.replace("TYPE",attrtype)
   o.write(line) 
o.close()
