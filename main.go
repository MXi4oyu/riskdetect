package main

import (
	"github.com/MXi4oyu/Utils/config"
	"fmt"
	"log"
	"github.com/MXi4oyu/riskdetect/webshell"
)

func main()  {
	config,err := config.NewConfig("D:/code/go/gopath/src/github.com/MXi4oyu/godome/rdini/config.ini")
	if err!=nil{
		log.Fatal(err.Error())
	}

	v:=config.String("yara_rule_path::whitelist")

	fmt.Println(v)
	//测试yara检测
	yarainfo:=webshell.Yara("D:/code/go/gopath/src/github.com/MXi4oyu/riskdetect/libs/php.yar","D:/phpStudy/WWW/")

	yl:=len(yarainfo)
	for i:=0;i<yl;i++{

		fmt.Println(yarainfo[i]["type"],"----",yarainfo[i]["path"])

	}

	//测试ssdeep检测
	ssdeepinfo:=webshell.Ssdeep("D:/code/go/gopath/src/github.com/MXi4oyu/riskdetect/libs/php.ssdeep","./")

	sl:=len(ssdeepinfo)

	for i:=0;i<sl;i++{
		fmt.Println(ssdeepinfo[i]["type"],"----",ssdeepinfo[i]["path"],"----",ssdeepinfo[i]["like"])
	}


}
