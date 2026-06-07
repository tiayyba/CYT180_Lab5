# CYT180 – Lab 5 — Hadoop & HBase Lab: Cloudera VM Setup and Hands-On Practice
**Weight:** 3% <br>
**Work Type:** Individual <br>
**Submission Format:** In class demonstartion: students are required to **install, configure, and demonstrate HBase operations live during class**, along with explaining key concepts <br>


## Table of Contents

1. [Introduction & Rationale](#-introduction--rationale)
2. [Real-World Usage of HBase](#-real-world-usage-of-hbase)
3. [Key Concepts: HDFS vs HBase](#-key-concepts-hdfs-vs-hbase)
4. [HBase Data Model](#-hbase-data-model)
5. [Setup Instructions](#-Setup-Instructions)
6. [Getting Started with HBase](#-hands-on-exercises)
   - [Exercise 1: Create a Table](#exercise-1-create-a-table)
   - [Exercise 2: Insert Data](#exercise-2-insert-data)
   - [Exercise 3: Query Data](#exercise-3-query-data)
   - [Exercise 4: Delete Data](#exercise-4-delete-data)
7. [Reflection Questions](#-reflection-questions)
8. [Lab Checklist](#-lab-checklist)

---

## Lab Objectives

By the end of this lab, students will be able to:

1. **Understand the limitations of HDFS** and explain why HBase was introduced as a complementary technology within the Hadoop ecosystem.
2. **Install and configure** Oracle VirtualBox and the Cloudera QuickStart VM to create a functional Hadoop/HBase development environment.
3. **Launch and navigate the HBase shell** to interact with a running HBase instance on the Cloudera VM.
4. **Design and create an HBase table** using column families, demonstrating an understanding of HBase's column-oriented data model.
5. **Perform core HBase operations** — including inserting, querying, and deleting data — using the HBase shell commands `put`, `get`, `scan`, and `delete`.
6. **Compare HBase with traditional relational databases**, articulating the differences in schema design, scalability, and use cases.
7. **Demonstrate a working HBase environment**  communicating both the technical steps and the conceptual reasoning behind them.

---

## Introduction & Rationale

As organizations began generating massive volumes of data — from web interactions and user activity to sensor logs — traditional relational databases (RDBMS) proved inadequate. These systems require **predefined schemas**, scale vertically (which is costly), and struggle to handle billions of rows or sparse datasets efficiently.

To address these challenges, Google introduced **BigTable**, a distributed storage system built for large-scale structured data. HBase was later developed as an open-source implementation inspired by BigTable, designed to run on top of Hadoop's Distributed File System (**HDFS**).

HBase enables **real-time random read/write access to massive datasets** — something HDFS alone cannot provide. While HDFS is optimized for high-throughput batch processing, it is **immutable**: once a file is written, it cannot be modified without rewriting it entirely. This makes HDFS unsuitable for applications requiring frequent updates.

HBase, by contrast, allows direct modification at the row level. Updating a single value in HDFS requires rewriting an entire file; in HBase, it takes a single command and happens instantly. Understanding this distinction is central to this lab.

---

## Real-World Usage of HBase

HBase has been widely adopted in large-scale enterprise systems where massive datasets and real-time access are required. Companies such as **Facebook, Twitter, LinkedIn, and Yahoo** have used HBase for applications including:

- **Messaging systems** — storing and retrieving billions of messages efficiently
- **Time-series analytics** — tracking user events and behavioral patterns over time
- **Activity feeds** — continuously writing and querying user activity streams in real time
- **IoT data storage** — handling constant streams of sensor data requiring rapid retrieval

> **Note:** While HBase remains relevant and is a foundational NoSQL technology, many modern systems are moving toward Cassandra, DynamoDB, and cloud-native data warehouses. Understanding HBase gives you the conceptual grounding to work with any of these systems.

---

##  Key Concepts: HDFS vs HBase

| Feature | HDFS | HBase |
|---|---|---|
| **Purpose** | Store large files, batch processing | Real-time read/write access |
| **Mutability** | Immutable (no in-place updates) | Mutable (row-level updates) |
| **Access Pattern** | Sequential reads/writes | Random reads/writes |
| **Best For** | MapReduce jobs, log archiving | Messaging, transactions, user profiles |
| **Built On** | Standalone distributed filesystem | Built on top of HDFS |

HDFS is the foundation — it stores the actual data on disk across nodes. HBase sits on top of HDFS and provides the table structure and real-time access layer. They work **together**, not against each other.

---

##  HBase Data Model

HBase uses a **column-oriented data model** that differs significantly from traditional relational databases:

- **Tables** — Data is organized into tables, similar to RDBMS
- **Row Key** — Each row has a unique identifier (the row key), used for fast lookups
- **Column Families** — Instead of fixed columns, HBase uses column families (e.g., `info`, `metrics`). These must be defined when the table is created.
- **Columns** — Columns live inside column families and can be added dynamically (no fixed schema required)
- **Versioning** — HBase automatically stores multiple versions of a cell's value using **timestamps**, allowing retrieval of historical data

**Example structure** for a student table:

```
Row Key     | info:name     | info:grade   | info:major
------------|---------------|--------------|------------
student_001 | Alice Johnson | A            | Computer Science
student_002 | Bob Smith     | B+           | Data Science
student_002 | Maija Sam     |              | Data Science
```

Unlike a relational database, not every row needs to have every column — HBase handles **sparse data** efficiently.

---

##  Setup Instructions

### Step 1: Install Oracle VirtualBox

- Download Oracle VirtualBox from the official website: 🔗 https://www.virtualbox.org/wiki/Downloads
- Select the version matching your operating system (Windows, macOS, or Linux) and install using the default settings.

---

### Step 2: Download Cloudera QuickStart VM

- Download the Cloudera QuickStart VM, which comes pre-configured with Hadoop, HDFS, HBase, and other ecosystem tools: 🔗 https://downloads.cloudera.com/demo_vm/virtualbox/cloudera-quickstart-vm-5.13.0-0-virtualbox.zip
- The file is approximately **5 GB** as a `.zip` archive — use a stable internet connection.
- After downloading: extract the `.zip` file. Youu will find a folder containing an **`.ovf` file** — this is what you will use in the next step.

---

### Step 3: Import VM into VirtualBox

1. Open Oracle VirtualBox
2. Click **File → Import Appliance**
3. Browse to the extracted folder and select the **`.ovf` file**
4. Click **Next** and click **Finish**. Wait for the process to complete — this may take several minutes

---

### Step 4: Configure Virtual Machine Settings

Before starting the VM, verify the following settings by selecting the VM and clicking **Settings**:

**System**
- Go to **Settings → System → Motherboard**: set RAM to at least **5120 MB (5 GB)**
- Go to **Settings → System → Processor**: set at least **2 CPU cores****Display**
- Go to **Settings → Display**: set Video Memory to **128 MB**
- Use **NAT** for basic connectivity (default)


Cloudera services are resource-intensive on a single-node setup. Allocating less than 5 GB of RAM will result in slow or failed service starts.


---

### Step 5: Start the Cloudera VM and Launch Cloudera Express

Select the imported VM and click **Start**. The VM will boot into a Linux desktop. This may take **2–5 minutes** on first launch.
Once the desktop loads, open a **Terminal** and run the following command to switch to Cloudera Express and restart all cluster services:

```bash
sudo /home/cloudera/cloudera-manager --express --force
```

This command shuts down existing services, switches the edition to **Cloudera Express**, and restarts the SCM Server and Agents. This process can take **3–5 minutes**. Wait until the terminal confirms services have restarted before proceeding.
Cloudera uses SCM server. Unlike standard Apache Hadoop where you manually start services using shell scripts, Cloudera uses the **SCM (Service Control Manager) Server** to manage all services centrally. The SCM Server communicates instructions to SCM Agents running on each node, which handle the actual starting and stopping of services. On this single-node VM, both the server and agent run on the same machine.

---

### Step 6: Access the Cloudera Admin Console

Once the SCM components are active, open the browser inside the VM and navigate to:

```
http://localhost:7180
```

Log in with the default credentials:

```
Username: cloudera
Password: cloudera
```

This is the **Cloudera Manager Admin Console** — a web UI where you can monitor and manage all cluster services.

---

### Step 7: Remove Unnecessary Services (Recommended)

Because this is a single-node setup, running all services simultaneously is very resource-heavy. To improve performance, remove the following services from Cloudera Manager:

- **Key-Value Store Indexer**
- **Solr**
- **Sqoop 2**

For each service:
1. Click on the service name in the Admin Console
2. Select **Actions → Delete**
3. Confirm the deletion

Please note that **Solr and Sqoop 2:** are used internally by **Hue**. When you attempt to delete them, Cloudera Manager will display a **"Configure Service Dependency"** button instead of proceeding. Click it — this loads the Hue configuration page where the dependency is listed. Set the value to **None** and save. Once saved, return and delete the service as normal.

Removing these services frees up significant memory and CPU, making the remaining services — including HBase — run noticeably faster.

---

### Step 8: Restart the Cluster and Verify

After removing unnecessary services, restart the cluster:

1. In the Admin Console, click **Actions → Restart** at the cluster level
2. Wait for all remaining services to show a **green status**

You can also verify service status from the terminal:

```bash
sudo service cloudera-scm-server status
sudo service cloudera-scm-agent status
```

Both should return `running`. Once all services are green, your environment is ready to proceed.

---

### Step 9: Open the HBase Shell

Open a Terminal inside the VM and launch the interactive HBase shell:

```bash
hbase shell
```

You should see a prompt like:

```
HBase Shell; enter 'help<RETURN>' for list of supported commands.
Type "exit<RETURN>" to leave the HBase Shell
Version ...

hbase(main):001:0>
```

You are now ready to begin the hands-on exercises. All commands in the next section are entered at this prompt.

---

## Getting Started with HBase 

> All commands are run inside the **HBase shell** unless stated otherwise.

---

### Exercise 1: Create a Table

In HBase, tables must be created with at least one **column family**. In this exercise, you will create a table called `students` with a column family called `info`.

**Command:**

```hbase
create 'students', 'info'
```

**Verify the table was created:**

```hbase
list
```

You should see `students` in the output.

**Check table details:**

```hbase
describe 'students'
```

This shows the table structure including the column family and its default settings.

> **What's happening:** HBase is registering the table metadata and preparing storage regions on HDFS. The column family `info` is the container under which all columns for this table will live.

---

### Exercise 2: Insert Data

Use the `put` command to insert data. Each `put` targets a specific **table**, **row key**, **column** (in `family:qualifier` format), and **value**.

**Insert three student records:**

```hbase
put 'students', 'student_001', 'info:name', 'Alice Johnson'
put 'students', 'student_001', 'info:grade', 'A'
put 'students', 'student_001', 'info:major', 'Computer Science'

put 'students', 'student_002', 'info:name', 'Bob Smith'
put 'students', 'student_002', 'info:grade', 'B+'
put 'students', 'student_002', 'info:major', 'Data Science'

put 'students', 'student_003', 'info:name', 'Carol White'
put 'students', 'student_003', 'info:grade', 'A-'
put 'students', 'student_003', 'info:major', 'Information Systems'
```

> **What's happening:** Each `put` writes a value to a specific cell (row + column intersection). HBase stores a **timestamp** automatically with every write — this is how versioning works. Running the same `put` again with a new value does not overwrite; it adds a new version.

---

### Exercise 3: Query Data

HBase provides two main ways to retrieve data: `get` (single row) and `scan` (multiple rows).

**Retrieve a single row by row key:**

```hbase
get 'students', 'student_001'
```

**Retrieve a specific column for a row:**

```hbase
get 'students', 'student_001', 'info:name'
```

**Scan the entire table** (returns all rows):

```hbase
scan 'students'
```

> **What is `scan`?** The `scan` command reads across multiple rows in sequence — similar to a `SELECT *` in SQL. It is powerful but can be slow on very large tables since it reads every row. For large datasets, scans are typically filtered using conditions. For this lab, scanning your small table is perfectly appropriate.

**Scan with a filter** (retrieve only names):

```hbase
scan 'students', {COLUMNS => 'info:name'}
```

> **What's happening:** `get` performs a direct row key lookup, which is very fast. `scan` reads sequentially across rows, which is useful when you don't know the row key in advance or want to retrieve a range of records.

---

### Exercise 4: Delete Data

HBase supports deleting a specific cell, a specific column in a row, or an entire row.

**Delete a specific cell (one column value):**

```hbase
delete 'students', 'student_003', 'info:grade'
```

**Verify the deletion:**

```hbase
get 'students', 'student_003'
```

The `info:grade` column should no longer appear.

**Delete an entire row:**

```hbase
deleteall 'students', 'student_002'
```

**Verify:**

```hbase
scan 'students'
```

`student_002` should no longer appear in results.

> **What's happening:** HBase deletions work through **tombstone markers** — a special marker is written to indicate the cell or row is deleted. The actual data is removed during a background process called **compaction**. This is why deletions in HBase are fast even on large datasets.

**When finished, exit the HBase shell:**

```hbase
exit
```

---

##  Reflection Questions

These questions are for your own understanding — **no submission required**. Think through your answers as you complete the lab.

1. Why can't HDFS be used on its own for applications that require frequent data updates? What limitation makes this impractical?

2. How does HBase's column family model differ from a traditional relational database schema? What advantage does this provide for sparse data?

3. You ran both `get` and `scan` commands in Exercise 3. In what scenario would you prefer `get` over `scan`, and why?

4. When you deleted a cell in Exercise 4, the data was not immediately removed from disk — it was marked with a tombstone. Why do you think HBase uses this approach instead of immediately erasing the data?

5. HBase stores multiple versions of each cell using timestamps. Think of a real-world use case where retrieving an older version of a record would be useful.

6. Based on what you learned, describe one situation where you would choose HBase over a traditional relational database, and one situation where a relational database would still be the better choice.

---

##  Lab Checklist

Use this checklist to confirm your setup and prepare for your live demonstration.

### Environment Setup

- [ ] Oracle VirtualBox installed and launching correctly
- [ ] Cloudera QuickStart VM downloaded and extracted using 7-Zip
- [ ] VM imported into VirtualBox with correct RAM (≥ 5 GB) and CPU (≥ 2 cores) settings
- [ ] Cloudera Express launched successfully via terminal command
- [ ] Cloudera Admin Console accessible at `localhost:7180`
- [ ] Unnecessary services (Key-Value Store, Solr, Sqoop 2) removed
- [ ] Cluster restarted and all services showing green status
- [ ] `hbase shell` opens successfully

### Live Demonstration

- [ ] Create the `students` table with the `info` column family
- [ ] Insert at least 3 rows of student data using `put`
- [ ] Retrieve a single row using `get`
- [ ] Scan the full table using `scan`
- [ ] Delete a specific cell and verify it is removed
- [ ] Delete an entire row and verify it is removed
- [ ] Able to explain the difference between HDFS and HBase when asked
- [ ] Able to explain what a column family is when asked

---

*Lab developed for Big Data Systems coursework. Setup based on Cloudera QuickStart VM and Apache HBase.*
