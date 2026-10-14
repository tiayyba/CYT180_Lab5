# CYT180 — Lab 5: Getting Started with PySpark in Google Colab

**Weight:** 3%  
**Work Type:** Individual  
**Submission Format:** screenshots.

---

## Introduction

**Apache Spark** is a free, open-source tool for processing large amounts of data. It can split the work across many computers (a **cluster**) so that big jobs finish faster.

You already know MapReduce from Week 4. MapReduce writes its in-between results to disk after every step. Spark keeps those in-between results **in memory (RAM)** whenever it can, so it is usually much faster.

You can write Spark programs in Python, Scala, Java or R. The Python version is called **PySpark**, and that is what we use in this lab.

You used **Pandas** in Week 3. Pandas works on one computer and the whole table must fit in that computer’s memory. Spark works in a similar way (tables with rows and columns), but it can handle data that is far too big for one computer.

PySpark documentation: http://spark.apache.org/docs/latest/api/python/

---

## Learning Objectives

By the end of this lab, you will be able to:

- Install Spark in Colab and start a Spark session.
- Explain what “hadoop3” in the Spark download name means, and why we do not need a Hadoop cluster in this lab.
- Find out which mode Spark is running in (local mode or a cluster).
- Load a CSV file into a Spark DataFrame and look at its columns and data types.
- Use common DataFrame operations: `select`, `filter`, `withColumn`, `groupBy`.
- Calculate a 7-day moving average with a window function.
- Explain the difference between a transformation and an action.

---

## Section 1 — Getting Started

Google Colab does not come with Spark. Before we can use it, we need three things:

1. **Java**, because Spark itself is written for the Java platform.
2. **Spark**, the engine that does the work.
3. A way for **Python** to talk to Spark (PySpark).

The steps below install these one by one.

### 1. Install Java 11

Spark 3.5 works best with Java 11, so we install it.

```python
# Install Java 11 (Spark needs Java to run)
!apt-get update -qq
!apt-get install -qq openjdk-11-jdk-headless
```

### 2. Download Spark 3.5.2

Next we download Spark and unpack it. The download is a ready-to-use copy of Spark. It already includes:

- the Spark engine,
- the `bin/` folder with programs such as `spark-submit` and `spark-shell`,
- PySpark (the Python part of Spark).

```python
# Download and unpack Spark 3.5.2
!wget -q https://archive.apache.org/dist/spark/spark-3.5.2/spark-3.5.2-bin-hadoop3.tgz
!tar xf spark-3.5.2-bin-hadoop3.tgz
```

The file is called `spark-3.5.2-bin-hadoop3`. This name means **“Spark version 3.5.2, ready to run, made to work with Hadoop 3.”** It does **not** mean that we are running Hadoop.

Here is what is really going on:

- Spark needs some code to **open and read files**. Instead of writing its own, Spark borrows this code from Hadoop. So the download includes a few **Hadoop library files**.
- These are only **files of code**. Nothing from Hadoop is started. There is **no HDFS** (no NameNode, no DataNodes) and **no YARN**.
- When we read a CSV file from the Colab disk, Spark uses that Hadoop code to open the file, just like a program uses a library.
- If one day we had a real Hadoop cluster, these same library files would let Spark read from HDFS and run on YARN. In this lab we don’t have one, and we don’t need one.

**In short:** Spark does the processing, the Colab disk stores the files, and Hadoop is only a set of helper files inside the Spark download.

### 3. Install findspark

PySpark is inside the Spark folder we just unpacked, but Python does not know where that folder is. The small package `findspark` helps Python find it.

```python
# findspark helps Python find the Spark folder
!pip -q install findspark
```

### 4. Set Environment Variables

Environment variables are settings that programs read when they start. Here we tell the system:

- where Java is (`JAVA_HOME`),
- where Spark is (`SPARK_HOME`),
- and we add both to `PATH`, so their programs can be run by name.

```python
import os

# Where Java is installed
os.environ["JAVA_HOME"] = "/usr/lib/jvm/java-11-openjdk-amd64"

# Where we unpacked Spark
os.environ["SPARK_HOME"] = "/content/spark-3.5.2-bin-hadoop3"

# Add Spark's and Java's programs to PATH
os.environ["PATH"] = os.environ["SPARK_HOME"] + "/bin:" + os.environ["PATH"]
os.environ["PATH"] = os.environ["JAVA_HOME"] + "/bin:" + os.environ["PATH"]

# Check that it worked
!java -version
!echo $SPARK_HOME
```

### 5. Start a Spark Session (in Local Mode)

A **SparkSession** is your connection to Spark. Every PySpark program creates one first. After that, everything you do with Spark (loading data, filtering, counting) goes through the variable `spark`.

When we create the session, we must also tell Spark **where to run**. This is called the **master** setting. In this lab, Spark runs in **local mode**: everything happens on the one Colab computer, and there is no cluster.

```python
import findspark
findspark.init()                      # 1. let Python find Spark

from pyspark.sql import SparkSession  # 2. bring in the SparkSession tool

spark = (SparkSession.builder         # 3. start building a session
         .appName("CYT180 Lab 5")     # 4. give our program a name
         .master("local[*]")          # 5. run in LOCAL MODE, using all CPU cores
         .getOrCreate())              # 6. create the session (or reuse one)

spark
```

What each line does:

1. `findspark.init()` helps Python locate the Spark installation so that it can import PySpark modules.
2. `from pyspark.sql import SparkSession` imports the SparkSession class from PySpark's SQL module. A SparkSession is the main entry point for working with Spark DataFrames and SQL queries. Even if we do not write SQL queries, we use SparkSession to create and manage our Spark session.
3. `SparkSession.builder` starts building the configuration for the Spark session we want to use.
4. `.appName("CYT180 Lab 5")` gives our program a name. On a cluster, this name shows up in the list of running jobs.
5. `.master("local[*]")` specifies where and how Spark will run. It sets the **mode**:
   - `local` means run on this one computer, rather than using a cluster manager.
   - `[*]` means use **all** available logical CPU cores on this computer to execute tasks in parallel.
6. `.getOrCreate()` creates the session. If one already exists, it reuses it instead of making a second one.

**So our Spark session runs in local mode (`local[*]`) on one Colab computer, using all of its CPU cores.**

Remember the Spark architecture from the lecture: a **driver** plans the work, **executors** do the work, and a **cluster manager** hands out machines. In local mode there is no cluster manager. The driver and the executor run together in **one program on the Colab computer**, and each CPU core works on one piece of the data at a time.

### 6. Check Your Setup and Confirm the Mode

Run this cell to make sure Spark is working and to **confirm which mode it is running in**:

```python
import pyspark
print("PySpark version:", pyspark.__version__)
print("Spark master (mode):", spark.sparkContext.master)
print("CPU cores on this computer:", os.cpu_count())
print("Tasks Spark runs at the same time:", spark.sparkContext.defaultParallelism)
print("Where Spark reads files from:", spark.sparkContext._jsc.hadoopConfiguration().get("fs.defaultFS"))
```

How to read the output:

- **Spark master (mode)** shows `local[*]`. This is how you know Spark is in local mode.
- **Tasks Spark runs at the same time** is the same as the number of CPU cores, because `[*]` means “use all cores”.
- **Where Spark reads files from** shows `file:///`. That is the Colab disk, **not HDFS**. This confirms that no Hadoop cluster is being used.

The master value is always the way to tell which mode Spark is in:

| Master value | Mode | Meaning |
|---|---|---|
| `local` | Local mode | One computer, 1 CPU core |
| `local[4]` | Local mode | One computer, 4 CPU cores |
| `local[*]` | Local mode | One computer, all CPU cores (**our lab**) |
| `spark://host:7077` | Standalone cluster | Spark’s own cluster manager, many computers |
| `yarn` | YARN cluster | Hadoop YARN manages the computers |
| `k8s://...` | Kubernetes cluster | Kubernetes manages the computers |

If you see an error in this step, go back and check the earlier steps (Java install, Spark download, environment variables).

---

## Section 2 — Creating a Simple DataFrame in PySpark

A **DataFrame** is a table with named columns, just like in Pandas. The difference is that Spark splits a DataFrame into smaller pieces called **partitions**. Different CPU cores (or, on a cluster, different computers) can work on different partitions at the same time. That is how Spark handles very large data.

In this section you will build a tiny DataFrame by hand, so you can see how Spark stores data and what types it gives each column.

### 1. Creating a DataFrame from a Python List (In Memory)

Usually Spark reads data from a file. Here there is **no file**. We type the rows straight into a normal Python list called `data`. That list lives in the notebook’s **memory (RAM)**. Then `spark.createDataFrame()` turns the list into a Spark DataFrame. This is what “in-memory” means here: the data comes from a variable in memory, not from a file on disk.

This is a quick way to make a small test table. In Section 3 you will load data from a real file instead.

```python
from pyspark.sql import functions as F

data = [
    ('John', '', 'Smith', '2000-01-01', 'M', 100000),
    ('Jane', '', 'Smith', '1990-01-01', 'F', 150000),
    ('Jonas', '', 'Smith', '1995-01-01', 'M', 120000),
]

columns = ["firstname", "middlename", "lastname", "dob", "gender", "salary"]

df_small = spark.createDataFrame(data=data, schema=columns)

df_small.show()          # print the table
df_small.printSchema()   # print each column's name and data type
```

- `show()` prints the rows as a table.
- `printSchema()` prints the **schema**: the list of columns and the data type Spark chose for each one (for example `string` for text and `long` for whole numbers).

### 2. Getting Summary Statistics

```python
df_small.describe().show()
```

`describe()` calculates the count, mean (average), standard deviation, minimum and maximum of each column. For text columns, only count, min and max make sense.

### 3. Review Questions

- What data type did Spark give each column? (Use `printSchema()`.)
- Add a new column called `age_rough` and show the updated DataFrame. Use:

  ```python
  df_small.withColumn("age_rough", F.year(F.current_date()) - F.year(F.to_date("dob"))).show()
  ```

---

## Section 3 — Load a Real Dataset (OWID COVID‑19) and Explore

Now we will use real data: the **Our World in Data (OWID) COVID-19** dataset. It has one row per country per day, with columns such as `new_cases` and `new_deaths`.

We will follow the usual steps of data analysis:  
**load → inspect → clean → explore**

> The file is about 100 MB and has data up to August 2024. The download may take a minute.
>
> Two things to know about this data: many countries reported cases only **once a week**, so you will see many days with `0`; and some countries stopped reporting some numbers, so you will see `NULL` (no value) in recent rows.

### 1. Download and Load the Dataset

First we download the CSV file to the Colab disk (`/content`). Then Spark reads it into a DataFrame.

`header=True` tells Spark that the first line has the column names.  
`inferSchema=True` tells Spark to look at the values and guess each column’s type (number, text, date) instead of treating everything as text.

```python
import requests, pathlib

url = "https://raw.githubusercontent.com/owid/covid-19-data/master/public/data/owid-covid-data.csv"
local_path = pathlib.Path("/content/owid-covid-data.csv")

# Download the file only if we don't have it yet
if not local_path.exists():
    r = requests.get(url, timeout=120)
    r.raise_for_status()
    local_path.write_bytes(r.content)

# Read the CSV into a Spark DataFrame
df = spark.read.csv(str(local_path), header=True, inferSchema=True)

print("Number of rows:", df.count())
df.printSchema()
```

Notice that the file path is a normal path on the Colab disk. Spark is not reading from HDFS.

### 2. Make Sure the `date` Column Is a Real Date

Look at the `date` column in the schema from step 1. Spark 3.5 usually recognizes values like `2024-08-04` and gives the column the **date** type. But with other date formats, or in older Spark versions, dates are read as plain text (**string**). You cannot sort by time or do date math on text.

So it is good practice to always convert the column yourself with `to_date()`. If it is already a date, nothing changes. If it is text, it becomes a date.

```python
df2 = df.withColumn("date", F.to_date("date"))
df2.select("location", "date", "new_cases", "new_deaths").show(5)
df2.printSchema()
```

- `withColumn("date", ...)` replaces the `date` column with the converted version.
- We save the result as a new DataFrame, `df2`. Spark DataFrames are never changed in place; each step makes a new one.

### 3. Create a Smaller Subset

Analysts often cut a big dataset down to just the part they need. Here we keep:

- only 5 countries: United States, Canada, India, Brazil, Italy,
- only the last 120 days of data.

```python
# Step 1: The countries we want
countries = ["United States", "Canada", "India", "Brazil", "Italy"]

# Step 2: Keep only rows for those countries
df_subset = df2.filter(F.col("location").isin(countries))

# Step 3: Find the latest date in that data
max_date = df_subset.agg(F.max("date")).first()[0]

# Step 4: Keep only the last 120 days before that date
N = 120
df_subset = df_subset.filter(F.col("date") >= F.date_sub(F.lit(max_date), N))

# Step 5: Look at the result
print("Number of rows in subset:", df_subset.count())
df_subset.select("location", "date", "new_cases", "new_deaths").show(10)
```

What each step does:

- `isin(countries)` keeps a row if its `location` is in our list.
- `agg(F.max("date"))` finds the largest (latest) date. `.first()[0]` takes that single value out so we can use it in Python.
- `date_sub(max_date, 120)` gives the date 120 days earlier. We keep only rows on or after it.
- `count()` and `show()` are the steps that actually make Spark do the work and give us an answer.

### 4. Filter and Sort the Data

Question: **What are the latest records for the United States?**

```python
(df2
 .filter(F.col("location") == "United States")   # keep only US rows
 .orderBy(F.desc("date"))                         # newest date first
 .select("location", "date", "new_cases", "new_deaths")
 .show(10))                                       # print 10 rows
```

- `filter` and `orderBy` are **transformations**: they describe what we want, but Spark does not do anything yet.
- `show()` is an **action**: it makes Spark run all the steps and print the result.

### 5. Group and Total: New Cases by Location

Question: **Which locations had the most cases in total?**

```python
agg_cases = (df2
    .groupBy("location")                                  # one group per location
    .agg(F.sum("new_cases").alias("total_new_cases"))     # add up new_cases in each group
    .orderBy(F.desc("total_new_cases"))                   # largest total first
)

agg_cases.show(10, truncate=False)
```

`groupBy` puts all rows with the same `location` together, and `agg(F.sum(...))` adds up `new_cases` inside each group. This is the same idea as the “reduce” step in MapReduce.

> Note: OWID also has rows for groups such as “World”, continents and income groups (for example “High-income countries”). These have very large totals, so they appear at the top.

### 6. Review Questions

- What data type does the `date` column have in `df` (step 1) and in `df2` (step 2)? Did `to_date()` change it? Why is it still a good idea to convert dates yourself?
- What data types did Spark give `location` and `new_cases`?
- Show the latest 10 records for Canada (change step 4).
- Change step 5 to calculate total new deaths by location.
- Why is it useful to make a smaller subset when working with a large dataset?

---

## Section 4 — Transformations, Actions, and a 7‑Day Moving Average

### 1. Transformations vs. Actions

Spark operations come in two kinds:

- **Transformations** describe a change to the data, but **do not run yet**. They return a new DataFrame.  
  Examples: `select`, `filter`, `orderBy`, `groupBy`, `withColumn`.
- **Actions** ask for a result. They **make Spark run** all the transformations before them.  
  Examples: `show`, `count`, `take`, `collect`.

A simple way to remember: transformations are writing the recipe; an action is cooking it.

### 2. Calculate a 7‑Day Moving Average of New Cases

Daily case numbers jump up and down a lot. A **7-day moving average** replaces each day’s number with the average of that day and the 6 days before it, which gives a smoother line.

**Step A: Describe the window**

```python
from pyspark.sql.window import Window

w = Window.partitionBy("location").orderBy("date").rowsBetween(-6, 0)
```

Read this line as:

- `partitionBy("location")`: treat each country separately.
- `orderBy("date")`: put each country’s rows in date order.
- `rowsBetween(-6, 0)`: for each row, look at the 6 rows before it and the row itself (7 days).

**Step B: Add the average as a new column**

```python
df3 = df2.withColumn("new_cases_7d_avg", F.avg("new_cases").over(w))

(df3
 .filter((F.col("location") == "United States") & (F.col("date") >= "2022-01-01"))
 .orderBy("date")
 .select("location", "date", "new_cases", "new_cases_7d_avg")
 .show(12))
```

What you should see:

- We start from January 2022, because the first months of 2020 are all zeros.
- Each row has the daily `new_cases` and the smoother `new_cases_7d_avg`.
- Look closely at `new_cases`: most days are `0`, and then one day has a very large number. That is because many countries reported their cases **once a week**, all on one day. The 7-day average spreads that weekly number over the whole week, which gives a much more realistic picture of each day.
- For the first 6 days there are not yet 7 days of data, so Spark averages only the days it has. Day 1 uses 1 day, day 2 uses 2 days, and so on.

### 3. Why Moving Averages Matter

Daily numbers can be uneven because of reporting delays, weekends, and batch updates. A 7-day average:

- removes much of this day-to-day noise,
- makes the overall trend easier to see,
- is used in health data, finance, and security monitoring (for example, average failed logins per day).

### 4. Review Questions

- Change the code to show the 5 dates in Canada with the highest `new_cases_7d_avg`.
- In one sentence, explain why moving averages are useful for data over time.

---

## Section 5 — Lazy Evaluation

When you write a transformation, Spark does not run it right away. It only writes it down in a **plan**. Spark waits until you call an action, then looks at the whole plan and runs it in the best order. This is called **lazy evaluation**.

**Look at the plan (this does NOT run the job)**

```python
agg_cases.explain(mode="formatted")
```

This prints the steps Spark plans to take for `agg_cases`. No data is processed yet.

**Run the plan with an action**

```python
# count() is an action, so Spark now runs the whole plan.
print("Number of rows in agg_cases:", agg_cases.count())
```

---

## Section 6 — Reflection Questions

Answer each question in 1–3 sentences. For questions that ask you to run code, include a screenshot of the output.

1. **Which mode?** How can you tell which mode your Spark session is running in? Write the line of code you used and the value it printed.
2. **local, local[2], local[*].** What is the difference between these three master values? Try it: run `spark.stop()`, create the session again with `.master("local[2]")`, and print `spark.sparkContext.defaultParallelism`. What number do you get now, and why?
3. **Driver and executors.** On a real cluster, the driver and the executors run on different computers. Where do they run in our Colab lab?
4. **Spark and Hadoop.** Our download was called `spark-3.5.2-bin-hadoop3`. Was Hadoop (HDFS or YARN) running during this lab? What does Hadoop provide in this download?
5. **Moving to a cluster.** Suppose you are given a Hadoop cluster with YARN and HDFS. What two things would you change to run this lab’s code there? (Hint: the master setting, and the file path.)
6. **Partitions.** Run `df2.rdd.getNumPartitions()`. How many partitions does `df2` have? Why does Spark split data into partitions?
8. **Spark or Pandas?** Give one situation where you would use Spark instead of Pandas, and one where Pandas is good enough.

---

## Submission Instructions

Submit screenshots that clearly show the work you completed in this lab. Your screenshots must include:

1. **Section 1:**
   - The output of step 6, showing the Spark master (mode), CPU cores, tasks at the same time, and where Spark reads files from.

2. **Section 2:**
   - `df_small.describe().show()`
   - Your added column `age_rough`

3. **Section 3:**
   - `df2.printSchema()` after converting the date
   - Your latest 10 records for Canada
   - Total new deaths by location

4. **Section 4:**
   - 7-day moving average for the United States (first 12 rows from 2022)
   - Top 5 days for Canada by `new_cases_7d_avg`

5. **Section 5:**
   - Your execution plan (`agg_cases.explain()`)
   - The action output (`agg_cases.count()`)

6. **Section 6:**
   - Answers to reflection questions.


7. Work must be complete, well organized and professionally presented. Screenshots that are too small, blurry, or show unrelated output can lose up to 100% of the marks.
