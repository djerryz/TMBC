
import sys
sys.path.append("../../")

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
    
tm = TM("WEB站点上用户评论功能")
tm.description = "这是一个非常简单的系统的威胁模型示例 - 基于网络的评论系统。用户输入评论，这些评论被添加到数据库并显示给用户。人们的想法是，尽管很简单，但这是一个足以表达有意义威胁的完整例子。"
tm.isOrdered = True # 自动排序所有数据流 
tm.mergeResponses = True # UI配置: 合并DFD中的edge边缘
tm.assumptions = [ # 假设列表
"", # 补充一些假设条件,包括使用场景，异常情况等
]
    
var_0=Boundary("b_Internet")
    
var_1=Boundary("b_Server/DB")
    
var_2=Boundary("b_Server/WEB")
    
var_3=Boundary("b_AWS VPC")
    
var_4 = Actor("e_用户")
var_4.inBoundary = var_0
    
var_5 = Server("e_Web服务器")
var_5.inBoundary = var_2
    
var_6 = Datastore("e_SQL数据库")
var_6.inBoundary = var_1
    
var_7 = Datastore("e_真实身份数据库")
var_7.inBoundary = var_1
    
var_8 = Lambda("e_AWS功能区")
var_8.inBoundary = var_3
    
_f = Dataflow(var_6, var_7, "f_数据库验证用户真实身份")
_f.protocol = "RDA-TCP"
_f.dstPort = 40234
_f.data = Data(
    "d_验证用户身份的令牌", classification=Classification.SECRET
)
_f.note = """验证用户是否是他们所说的用户。"""
_f.maxClassification = Classification.SECRET
    
_f = Dataflow(var_4, var_5, "f_用户输入评论 (*)")
_f.protocol = "HTTP"
_f.dstPort = 80
_f.data = Data(
    "d_在HTML或Markdown中的用户评论数据", classification=Classification.PUBLIC
)
_f.note = """这是一个存储和检索用户评论的简单web应用程序。"""
_f.maxClassification = Classification.PUBLIC
    
_f = Dataflow(var_5, var_6, "f_包含用户评论数据的Insert查询指令")
_f.protocol = "MySQL"
_f.dstPort = 3306
_f.data = Data(
    "d_包含用户评论数据的Insert查询指令", classification=Classification.PUBLIC
)
_f.note = """Web服务器在其SQL查询中插入用户注释，并将其存储在数据库中。"""
_f.maxClassification = Classification.PUBLIC
    
_f = Dataflow(var_6, var_5, "f_检索评论")
_f.protocol = "MySQL"
_f.dstPort = 80
_f.data = Data(
    "d_Web服务器从DB检索评论", classification=Classification.PUBLIC
)
_f.note = """这是一个存储和检索用户评论的简单web应用程序。"""
_f.maxClassification = Classification.PUBLIC
    
_f = Dataflow(var_5, var_4, "f_展示评论 (*)")
_f.protocol = "HTTP"
_f.dstPort = -1
_f.data = Data(
    "d_Web服务器向最终用户显示评论", classification=Classification.PUBLIC
)
_f.note = """"""
_f.maxClassification = Classification.PUBLIC
    
_f = Dataflow(var_8, var_6, "f_Serverless功能定期清理数据库")
_f.protocol = "MySQL"
_f.dstPort = 3306
_f.data = Data(
    "d_Serverless功能清除数据库", classification=Classification.PUBLIC
)
_f.note = """"""
_f.maxClassification = Classification.PUBLIC
    
if __name__ == "__main__":
    tm.process()
    