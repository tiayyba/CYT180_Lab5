# 🐘 Hadoop & HBase Lab: Cloudera VM Setup and Hands-On Practice

> **Course Lab** | Big Data Systems  
> Students are required to **install, configure, and demonstrate HBase operations live during class**, along with explaining key concepts.

---

## 📋 Table of Contents

1. [Introduction & Rationale](#-introduction--rationale)
2. [Real-World Usage of HBase](#-real-world-usage-of-hbase)
3. [Key Concepts: HDFS vs HBase](#-key-concepts-hdfs-vs-hbase)
4. [HBase Data Model](#-hbase-data-model)
5. [Setup Instructions](#-setup-instructions)
   - [Step 1: Install Oracle VirtualBox](#step-1-install-oracle-virtualbox)
   - [Step 2: Download Cloudera QuickStart VM](#step-2-download-cloudera-quickstart-vm)
   - [Step 3: Import VM into VirtualBox](#step-3-import-vm-into-virtualbox)
   - [Step 4: Configure VM Settings](#step-4-configure-virtual-machine-settings)
   - [Step 5: Start the Cloudera VM](#step-5-start-the-cloudera-vm)
   - [Step 6: Launch HBase](#step-6-launch-hbase)
   - [Step 7: Open the HBase Shell](#step-7-open-the-hbase-shell)
6. [Hands-On Exercises](#-hands-on-exercises)
   - [Exercise 1: Create a Table](#exercise-1-create-a-table)
   - [Exercise 2: Insert Data](#exercise-2-insert-data)
   - [Exercise 3: Query Data](#exercise-3-query-data)
   - [Exercise 4: Delete Data](#exercise-4-delete-data)
7. [Reflection Questions](#-reflection-questions)
8. [Lab Checklist](#-lab-checklist)

---

## 📖 Introduction & Rationale

As organizations began generating massive volumes of data — from web interactions and user activity to sensor logs — traditional relational databases (RDBMS) proved inadequate. These systems require **predefined schemas**, scale vertically (which is costly), and struggle to handle billions of rows or sparse datasets efficiently.

To address these challenges, Google introduced **BigTable**, a distributed storage system built for large-scale structured data. HBase was later developed as an open-source implementation inspired by BigTable, designed to run on top of Hadoop's Distributed File System (**HDFS**).

HBase enables **real-time random read/write access to massive datasets** — something HDFS alone cannot provide. While HDFS is optimized for high-throughput batch processing, it is **immutable**: once a file is written, it cannot be modified without rewriting it entirely. This makes HDFS unsuitable for applications requiring frequent updates.

HBase, by contrast, allows direct modification at the row level. Updating a single value in HDFS requires rewriting an entire file; in HBase, it takes a single command and happens instantly. Understanding this distinction is central to this lab.

---

## 🌐 Real-World Usage of HBase

HBase has been widely adopted in large-scale enterprise systems where massive datasets and real-time access are required. Companies such as **Facebook, Twitter, LinkedIn, and Yahoo** have used HBase for applications including:

- **Messaging systems** — storing and retrieving billions of messages efficiently
- **Time-series analytics** — tracking user events and behavioral patterns over time
- **Activity feeds** — continuously writing and querying user activity streams in real time
- **IoT data storage** — handling constant streams of sensor data requiring rapid retrieval

> **Note:** While HBase remains relevant and is a foundational NoSQL technology, many modern systems are moving toward Cassandra, DynamoDB, and cloud-native data warehouses. Understanding HBase gives you the conceptual grounding to work with any of these systems.

---

## ⚖️ Key Concepts: HDFS vs HBase

| Feature | HDFS | HBase |
|---|---|---|
| **Purpose** | Store large files, batch processing | Real-time read/write access |
| **Mutability** | Immutable (no in-place updates) | Mutable (row-level updates) |
| **Access Pattern** | Sequential reads/writes | Random reads/writes |
| **Best For** | MapReduce jobs, log archiving | Messaging, transactions, user profiles |
| **Built On** | Standalone distributed filesystem | Built on top of HDFS |

HDFS is the foundation — it stores the actual data on disk across nodes. HBase sits on top of HDFS and provides the table structure and real-time access layer. They work **together**, not against each other.

---

## 🗂️ HBase Data Model

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
```

Unlike a relational database, not every row needs to have every column — HBase handles **sparse data** efficiently.

---

## ⚙️ Setup Instructions

### Step 1: Install Oracle VirtualBox

Download Oracle VirtualBox from the official website:

🔗 https://www.virtualbox.org/wiki/Downloads

Select the version matching your operating system (Windows, macOS, or Linux) and install using the default settings.

> **Note:** During installation, your network interfaces may briefly reset — this is expected behavior.

Once installed, launch VirtualBox to confirm it opens correctly before proceeding.

---

### Step 2: Download Cloudera QuickStart VM

Download the Cloudera QuickStart VM, which comes pre-configured with Hadoop, HDFS, HBase, and other ecosystem tools:

🔗 https://www.cloudera.com/downloads/quickstart_vms.html

Select: **Cloudera QuickStart VM for VirtualBox**

The file will be in `.zip` or `.ova` format and is several GB in size. Use a stable internet connection.

- If downloaded as `.zip`, extract it to obtain the `.ova` file before proceeding.

---

### Step 3: Import VM into VirtualBox

1. Open Oracle VirtualBox
2. Click **File → Import Appliance**
3. Browse to and select the `.ova` file
4. Click **Next**
5. Before importing, set the following resources:
   - **RAM:** Minimum 4 GB (8 GB recommended)
   - **CPU:** Minimum 2 cores
6. Click **Import** and wait for the process to complete (this may take a few minutes)

---

### Step 4: Configure Virtual Machine Settings

Before starting the VM, verify the following settings by selecting the VM and clicking **Settings**:

**System**
- Go to **Settings → System → Motherboard**: confirm RAM is at least **4096 MB**
- Go to **Settings → System → Processor**: confirm at least **2 CPU cores** are assigned

**Display**
- Go to **Settings → Display**: set Video Memory to **128 MB**

**Network** *(optional)*
- Use **NAT** for basic internet access within the VM
- Use **Bridged Adapter** if you need the VM to be accessible from other machines on your network

---

### Step 5: Start the Cloudera VM

Select the imported VM and click **Start**.

The VM will boot into a Linux desktop environment. This may take **2–5 minutes** on first launch.

Once loaded, log in with the default credentials:

```
Username: cloudera
Password: cloudera
```

> If prompted at any point during boot, click through any configuration wizards using the default options.

---

### Step 6: Launch HBase

Once inside the Cloudera VM, open a **Terminal** window (right-click the desktop → Open Terminal, or find it in the taskbar).

Start the HBase service by running:

```bash
start-hbase.sh
```

Wait for the command to complete. You should see output confirming that HBase master and region servers have started. This may take **30–60 seconds**.

To verify HBase is running:

```bash
hbase status
```

Expected output will show `1 active master` and region server details.

---

### Step 7: Open the HBase Shell

Launch the interactive HBase shell:

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

## 🧪 Hands-On Exercises

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

## 💭 Reflection Questions

These questions are for your own understanding — **no submission required**. Think through your answers as you complete the lab.

1. Why can't HDFS be used on its own for applications that require frequent data updates? What limitation makes this impractical?

2. How does HBase's column family model differ from a traditional relational database schema? What advantage does this provide for sparse data?

3. You ran both `get` and `scan` commands in Exercise 3. In what scenario would you prefer `get` over `scan`, and why?

4. When you deleted a cell in Exercise 4, the data was not immediately removed from disk — it was marked with a tombstone. Why do you think HBase uses this approach instead of immediately erasing the data?

5. HBase stores multiple versions of each cell using timestamps. Think of a real-world use case where retrieving an older version of a record would be useful.

6. Based on what you learned, describe one situation where you would choose HBase over a traditional relational database, and one situation where a relational database would still be the better choice.

---

## ✅ Lab Checklist

Use this checklist to confirm your setup and prepare for your live demonstration.

### Environment Setup

- [ ] Oracle VirtualBox installed and launching correctly
- [ ] Cloudera QuickStart VM downloaded and extracted
- [ ] VM imported into VirtualBox with correct RAM (≥ 4 GB) and CPU (≥ 2 cores) settings
- [ ] VM boots successfully and desktop loads
- [ ] Terminal accessible inside the VM
- [ ] `start-hbase.sh` runs without errors
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
