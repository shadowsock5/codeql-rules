检测fastjson：
```ql
import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.UnsafeDeserializationQuery
import DataFlow::PathGraph



/**
 * The class `com.alibaba.fastjson.JSON`.
 */
class FastJson extends RefType {
    FastJson() { 
        this.hasQualifiedName("com.alibaba.fastjson", "JSON") or
        this.hasQualifiedName("com.alibaba.fastjson", "JSONObject")
    }
}

/** 
 * A call to a parse method of `JSON`. 
 * sink
 * */
class FastJsonParse extends MethodAccess {
    FastJsonParse() {
        exists(Method m |
            m.getDeclaringType() instanceof FastJson and
            (m.hasName("parse") or m.hasName("parseObject") or m.hasName("parseArray")) and
            m = this.getMethod()
        )
    }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, UnsafeDeserializationConfig conf
where conf.hasFlowPath(source, sink)
select sink.getNode().(UnsafeDeserializationSink).getMethodAccess(), source, sink,
 "Fastjson of $@.", source.getNode(), "user input"
```


检测权限校验：
```ql
import java



from Method m

where 
m.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestMapping")

and 
not m.getAnAnnotation().getType().hasQualifiedName("org.springframework.security.access.prepost", "PreAuthorize")
select m
```

参考：
- [Java : add fastjson detection. Improve RemoteFlowSource class, support SpringMvc](https://github.com/github/securitylab/issues/119)
