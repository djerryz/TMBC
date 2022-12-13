
import sys
sys.path.append("..")

from pytm import (
    TM,
    Actor,
    Boundary,
    Classification,
    Data,
    Dataflow,
    Datastore,
    Lambda,
    Server,
    DatastoreType,
)

# 定义全景
tm = TM("WEB站点上用户评论功能")
tm.description = "这是一个非常简单的系统的威胁模型示例 - 基于网络的评论系统。用户输入评论，这些评论被添加到数据库并显示给用户。人们的想法是，尽管很简单，但这是一个足以表达有意义威胁的完整例子。"
tm.isOrdered = True # 自动排序所有数据流 
tm.mergeResponses = True # UI配置: 合并DFD中的edge边缘
tm.assumptions = [ # 假设列表
"", # 补充一些假设条件,包括使用场景，异常情况等
]

# 定义信任边界
internet = Boundary("Internet")
server_db = Boundary("Server/DB")
server_db.levels = [2]
server_web = Boundary("Server/WEB")
server_web.levels = [2]
vpc = Boundary("AWS VPC")

# 定义实体
## 操作者实体
user = Actor("用户")
user.inBoundary = internet # 实体归属到网络信任边界内
user.levels = [2]
## 服务器实体
web = Server("Web服务器")
web.inBoundary = server_web # 实体归属到server_web信任边界内
web.levels = [2]
web.OS = "Ubuntu" # 配置信息
web.controls.isHardened = True
web.controls.sanitizesInput = False
web.controls.encodesOutput = True
web.controls.authorizesSource = False
web.sourceFiles = ["pytm/json.py", "docs/template.md"]
## 数据库实体
db = Datastore("SQL数据库")
db.OS = "CentOS"
db.controls.isHardened = False
db.inBoundary = server_db
db.type = DatastoreType.SQL
db.inScope = True
db.maxClassification = Classification.RESTRICTED
db.levels = [2]
## 数据库实体-2
secretDb = Datastore("真实身份数据库")
secretDb.OS = "CentOS"
secretDb.sourceFiles = ["pytm/pytm.py"]
secretDb.controls.isHardened = True
secretDb.inBoundary = server_db
secretDb.type = DatastoreType.SQL
secretDb.inScope = True
secretDb.storesPII = True
secretDb.maxClassification = Classification.TOP_SECRET
## 功能区实体
my_lambda = Lambda("AWS功能区")
my_lambda.controls.hasAccessControl = True
my_lambda.inBoundary = vpc
my_lambda.levels = [1, 2]

# 定义数据流
## 用户凭证数据
token_user_identity = Data(
    "验证用户身份的令牌", classification=Classification.SECRET  # 数据类级: 机密
)
## 流
db_to_secretDb = Dataflow(db, secretDb, "数据库验证用户真实身份")
db_to_secretDb.protocol = "RDA-TCP"
db_to_secretDb.dstPort = 40234
db_to_secretDb.data = token_user_identity
db_to_secretDb.note = "验证用户是否是他们所说的用户。"
db_to_secretDb.maxClassification = Classification.SECRET
## 用户评论数据
comments_in_text = Data(
    "在HTML或Markdown中的用户评论数据", classification=Classification.PUBLIC
)
## 流
user_to_web = Dataflow(user, web, "用户输入评论 (*)")
user_to_web.protocol = "HTTP"
user_to_web.dstPort = 80
user_to_web.data = comments_in_text
user_to_web.note = "这是一个存储和检索用户评论的简单web应用程序。"
## 数据库指令操作数据
query_insert = Data("包含用户评论数据的Insert查询指令", classification=Classification.PUBLIC)
## 流
web_to_db = Dataflow(web, db, "包含用户评论数据的Insert查询指令")
web_to_db.protocol = "MySQL"
web_to_db.dstPort = 3306
web_to_db.data = query_insert
web_to_db.note = (
    "Web服务器在其SQL查询中插入用户注释，并将其存储在数据库中。"
)
## 数据库返回的评论数据
comment_retrieved = Data(
    "Web服务器从DB检索评论", classification=Classification.PUBLIC
)
## 流
db_to_web = Dataflow(db, web, "检索评论")
db_to_web.protocol = "MySQL"
db_to_web.dstPort = 80
db_to_web.data = comment_retrieved
db_to_web.responseTo = web_to_db
## web服务器返回给用户的数据
comment_to_show = Data(
    "Web服务器向最终用户显示评论", classifcation=Classification.PUBLIC
)
## 流
web_to_user = Dataflow(web, user, "展示评论 (*)")
web_to_user.protocol = "HTTP"
web_to_user.data = comment_to_show
web_to_user.responseTo = user_to_web
## web服务器返回给用户的数据
clear_op = Data("Serverless功能清除数据库", classification=Classification.PUBLIC)
## 流
my_lambda_to_db = Dataflow(my_lambda, db, "Serverless功能定期清理数据库")
my_lambda_to_db.protocol = "MySQL"
my_lambda_to_db.dstPort = 3306
my_lambda_to_db.data = clear_op

if __name__ == "__main__":
    tm.process()
