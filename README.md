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

from DataFlow::PathNode source, DataFlow::PathNode sink, UnsafeDeserializationConfig conf, FastJsonParse m
where conf.hasFlowPath(source, sink)
select m, source, sink
```

其实codeql官方有这个库，直接用就行，
```
import java
import semmle.code.java.security.UnsafeDeserializationQuery
import DataFlow::PathGraph

from DataFlow::PathNode source, DataFlow::PathNode sink, UnsafeDeserializationConfig conf
where conf.hasFlowPath(source, sink)
select sink.getNode().(UnsafeDeserializationSink).getMethodAccess(), source, sink,"Unsafe deserialization of $@.", source.getNode(), "user input"
```

java\ql\lib\semmle\code\java\security\UnsafeDeserializationQuery.qll

有很多东西的反序列化：
![268fc7134b45f8965a071e9a91a0db0](https://user-images.githubusercontent.com/30398606/144951846-32d5ff30-870c-41f6-8e9e-1d6929f69785.png)





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


用于是否有某些校验的检查：
```
// java\ql\src\experimental\Security\CWE\CWE-552\UnsafeUrlForward.ql
private class StartsWithSanitizer extends DataFlow::BarrierGuard {
  StartsWithSanitizer() {
    this.(MethodAccess).getMethod().hasName("startsWith") and
    this.(MethodAccess).getMethod().getDeclaringType() instanceof TypeString and
    this.(MethodAccess).getMethod().getNumberOfParameters() = 1
  }

  override predicate checks(Expr e, boolean branch) {
    e = this.(MethodAccess).getQualifier() and branch = true
  }
}
```


### log4j对java-sec-code的查询结果

![image](https://user-images.githubusercontent.com/30398606/146521688-0c83c567-d9eb-4a1d-86b9-236bfd8b7eca.png)


参考：
- [Java : add fastjson detection. Improve RemoteFlowSource class, support SpringMvc](https://github.com/github/securitylab/issues/119)
- [Codeql学习笔记](https://github.com/safe6Sec/CodeqlNote)
