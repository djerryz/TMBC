import copy

var_map = {}# 避免特殊字符导致变量赋值失败
def md5_(str_):
    global var_map
    if str_ in var_map:
        return var_map[str_]
    else:
        this_var = "var_{}".format(str(len(var_map)))
        var_map[str_] = this_var
        return this_var
    # import hashlib , eg 263768f79082d2ad28b7f7dba910223a will failed
    # return hashlib.md5(str_.encode()).hexdigest()

def json_to_model_main(this_,result_name,header_str):    
    base_model = '''
tm = TM("{}")
tm.description = "{}"
tm.isOrdered = True # 自动排序所有数据流 
tm.mergeResponses = True # UI配置: 合并DFD中的edge边缘
tm.assumptions = [ # 假设列表
"", # 补充一些假设条件,包括使用场景，异常情况等
]
    '''

    boundary_model = '''
{}=Boundary("{}")
    '''

    element_model = '''
{} = {}("{}")
{}.inBoundary = {}
    '''

    dataflow_model = '''
_f = Dataflow({}, {}, "{}")
_f.protocol = "{}"
_f.dstPort = {}
_f.data = Data(
    "{}", classification=Classification.{}
)
_f.note = """{}"""
_f.maxClassification = Classification.{}
    '''

    # 处理base
    whole_str = """
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
    """
    whole_str += copy.deepcopy(base_model).format(
        this_["base"]["title"],
        this_["base"]["desc"]
    )

    # 处理边界
    boundary_str_part2 = """"""
    for one_bound in this_["boundarys"]:
        whole_str += copy.deepcopy(boundary_model).format(
            md5_(one_bound),
            one_bound
        )
        _ = this_["boundarys"][one_bound]
        if "in" in _:
            boundary_str_part2 += """{}.inBoundary = {}\n""".format(
                md5_(one_bound),
                md5_(_["in"])
            )
    whole_str+=boundary_str_part2

    # 处理实体
    for one_element in this_["elements"]:
        _ = this_["elements"][one_element]
        whole_str += copy.deepcopy(element_model).format(
            md5_(one_element),
            _["roler"],
            one_element,
            md5_(one_element),
            md5_(_["in"])
        )

    # 处理流
    for one_dataflow in this_["dataflows"]:
        _ = this_["dataflows"][one_dataflow]
        whole_str += copy.deepcopy(dataflow_model).format(
            md5_(_["flowto"][0]),
            md5_(_["flowto"][1]),
            _["flowto"][2],
            _["flowdesc"]["protocol"],
            _["flowdesc"]["dstPort"],
            _["flowdesc"]["data"][0],
            _["flowdesc"]["data"][1],
            _["flowdesc"]["note"],
            _["flowdesc"]["maxClassification"],
        )

    whole_str += '''
if __name__ == "__main__":
    tm.process()
    '''

    with open(result_name, "w", encoding="utf_8") as f:
        f.write(header_str + whole_str)