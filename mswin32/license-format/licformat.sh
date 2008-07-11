#!/bin/bash

script_dir=`dirname $0`

sed -f $script_dir/licsed_1 $1 | tr '\n' ' '| awk 'NR==1{printf("\n%s", $0) }' |

awk '{for (i=1&&j=2; i <= NF; i++&&j++) if($i=="SDFGHJdblnewline"){printf("\n\n")}
else if($i=="oSDFGHbullet"){printf(" \no ")}
else if($i=="Copyright" && $j=="(C)"){printf("\n%s ",$i)}
else if($i=="author" && $j=="Gnomovision"){printf("author\n")}
else if($i=="1989" && $j== "Ty"){printf("1989\n")}
else{printf("%s ",$i)}}' |

sed -f $script_dir/licsed_2
