this_ = {
    "base":{
        "title":"WEB站点上用户评论功能",
        "desc": "这是一个非常简单的系统的威胁模型示例 - 基于网络的评论系统。用户输入评论，这些评论被添加到数据库并显示给用户。人们的想法是，尽管很简单，但这是一个足以表达有意义威胁的完整例子。"
    },
    "boundarys": {
        "b_Internet":{

        },
        "b_Server/DB":{

        },
        "b_Server/WEB":{

        },
        "b_AWS VPC":{

        }
    },
    "elements":{
        "e_用户":{
            "roler": "Actor",
            "in": "b_Internet"
        },
        "e_Web服务器":{
            "roler": "Server",
            "in": "b_Server/WEB"
        },
        "e_SQL数据库":{
            "roler": "Datastore",
            "in": "b_Server/DB"
        },
        "e_真实身份数据库":{
            "roler": "Datastore",
            "in": "b_Server/DB"
        },
        "e_AWS功能区":{
            "roler": "Lambda",
            "in": "b_AWS VPC"
        }
    },
    "dataflows": {
        "1": {
            "flowto": ["e_SQL数据库","e_真实身份数据库","f_数据库验证用户真实身份"],
            "flowdesc": {
                "protocol": "RDA-TCP",
                "dstPort": 40234,
                "data": [
                    "d_验证用户身份的令牌", 
                    "SECRET"
                ],
                "note": """验证用户是否是他们所说的用户。""",
                "maxClassification": "SECRET"
            }
        },
        "2": {
            "flowto": ["e_用户","e_Web服务器","f_用户输入评论 (*)"],
            "flowdesc": {
                "protocol": "HTTP",
                "dstPort": 80,
                "data": [
                    "d_在HTML或Markdown中的用户评论数据", 
                    "PUBLIC"
                ],
                "note": """这是一个存储和检索用户评论的简单web应用程序。""",
                "maxClassification": "PUBLIC"
            }
        },
        "3": {
            "flowto": ["e_Web服务器","e_SQL数据库","f_包含用户评论数据的Insert查询指令"],
            "flowdesc": {
                "protocol": "MySQL",
                "dstPort": 3306,
                "data": [
                    "d_包含用户评论数据的Insert查询指令", 
                    "PUBLIC"
                ],
                "note": """Web服务器在其SQL查询中插入用户注释，并将其存储在数据库中。""",
                "maxClassification": "PUBLIC"
            }
        },
        "4": {
            "flowto": ["e_SQL数据库","e_Web服务器","f_检索评论"],
            "flowdesc": {
                "protocol": "MySQL",
                "dstPort": 80,
                "data": [
                    "d_Web服务器从DB检索评论", 
                    "PUBLIC"
                ],
                "note": """这是一个存储和检索用户评论的简单web应用程序。""",
                "maxClassification": "PUBLIC"
            }
        },
        "5": {
            "flowto": ["e_Web服务器","e_用户","f_展示评论 (*)"],
            "flowdesc": {
                "protocol": "HTTP",
                "dstPort": -1,
                "data": [
                    "d_Web服务器向最终用户显示评论", 
                    "PUBLIC"
                ],
                "note": """""",
                "maxClassification": "PUBLIC"
            }
        },
        "6": {
            "flowto": ["e_AWS功能区","e_SQL数据库","f_Serverless功能定期清理数据库"],
            "flowdesc": {
                "protocol": "MySQL",
                "dstPort": 3306,
                "data": [
                    "d_Serverless功能清除数据库", 
                    "PUBLIC"
                ],
                "note": """""",
                "maxClassification": "PUBLIC"
            }
        },

    }
}

import sys
sys.path.append("../../")
from json_to_model import json_to_model_main



header_str = '''
import sys
sys.path.append("../../")
'''
json_to_model_main(this_, "new_web_user_comment_json_model.py", header_str)