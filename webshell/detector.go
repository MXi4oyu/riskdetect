package webshell

import (
	"github.com/MXi4oyu/Utils/subprocess"
	"fmt"
	"github.com/MXi4oyu/Utils/cnencoder/gb18030"
	"context"
	"time"
	"strings"
)

func Webshelldetect(shell_path ,ssdeep_features_path,yara_rule_path string) []string {

	res1:=make([]string,10,50)
	res2:=make([]string,10,50)

	res1=append(res1,res2[:]...)
	return res1
}

func Yara(rule_path,dir_path string) ([]map[string]string)  {

	res:=make(map[string]string)
	funny_res := make([]map[string]string,0,100)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(6000)*time.Second)
	defer cancel()

	str,err:=subprocess.RunCommand(ctx,"D:/code/go/gopath/src/github.com/MXi4oyu/riskdetect/libs/tools/yara.exe",rule_path,"-r",dir_path)
	if err!=nil{
		fmt.Println(err.Error())
	}

	line:=gb18030.Decode(str)

	s:=strings.Split(line,"\n")

	for _,file_dir:=range s{

		var file_type,file_path string

		if len(file_dir)>0{
			ss:=strings.Split(file_dir," ")
			file_type=ss[0]
			file_path=ss[1]

			res["type"]=file_type
			res["path"]=file_path
			funny_res=append(funny_res,res)
		}
	}

	return funny_res

}

func Ssdeep(rule_path,dir_path string) ([]map[string]string)  {

	res:=make(map[string]string)
	funny_res := make([]map[string]string,0,100)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(6000)*time.Second)
	defer cancel()

	str,err:=subprocess.RunCommand(ctx,"D:/code/go/gopath/src/github.com/MXi4oyu/riskdetect/libs/tools/ssdeep.exe","-bsm",rule_path,"-r",dir_path,"-t","45","-c")
	if err!=nil{
		fmt.Println(err.Error())
	}

	line:=gb18030.Decode(str)

	s:=strings.Split(line,"\n")

	for _,file_dir:=range s{

		var file_type,file_path,file_like string

		if len(file_dir)>0{
			ss:=strings.Split(file_dir," ")
			file_type=ss[2]
			file_path=ss[0]
			file_like=ss[3]
			file_like=strings.Replace(file_like,"(","",-1)
			file_like=strings.Replace(file_like,")","",-1)

			res["type"]=strings.Split(file_type,":")[2]
			res["path"]=file_path
			res["like"]=file_like
			funny_res=append(funny_res,res)
		}
	}

	return funny_res
}