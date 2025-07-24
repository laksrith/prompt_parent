import sqlContext.implicits._

val
df = sc.parallelize(List("瀚聪Marylène", "瀚聪")).toDF("unicode_col")

val
protectUnicodeUDF = sqlContext.udf.register(
    "ptyProtectUnicode",
    com.protegrity.spark.udf.ptyProtectUnicode
_)

df.registerTempTable("unicode_test")

sqlContext
.sql(
    "select ptyProtectUnicode(unicode_col, 'Token_Unicode') as protected from unicode_test")
.show(false)
