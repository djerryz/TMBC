## 一、系统描述
{tm.description}
{tm.assumptions:if:
|Assumptions|
|-----------|
{tm.assumptions:repeat:|{{item}}| 
}
}


## 二、数据流图-0级DFD

!!!!!!!!!!!!说明，此处请用--seq参数生成图片后，自行在此处引入!!!!!!!!!!!!

### 数据流列表

|Name|From|To |Data|Protocol|Port|
| ---- | ---- | ---- | ---- | ---- | ---- |
{dataflows:repeat:|{{item.name}}|{{item.source.name}}|{{item.sink.name}}|{{item.data}}|{{item.protocol}}|{{item.dstPort}}|
}

## 三、数据源列表

|Name|Description|Classification|
| ---- | ---- | ---- |
{data:repeat:|{{item.name}}|{{item.description}}|{{item.classification.name}}|
}

## 四、潜在威胁
{findings:repeat:
<details>
  <summary>   {{item.threat_id}}   --   {{item.description}}</summary>
  <h6> Targeted Element </h6>
  <p> {{item.target}} </p>
  <h6> Severity </h6>
  <p>{{item.severity}}</p>
  <h6>Example Instances</h6>
  <p>{{item.example}}</p>
  <h6>Mitigations</h6>
  <p>{{item.mitigations}}</p>
  <h6>References</h6>
  <p>{{item.references}}</p>
  &nbsp;
  &nbsp;
  &emsp;
</details>
}|
