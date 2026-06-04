# Hadoop & HBase Lab: Cloudera VM Setup and Hands-On Practice

This lab is designed to provide students with both **practical experience** and **conceptual understanding** of HBase within the Hadoop ecosystem. By completing this lab, students will learn not only how to execute HBase commands, but also why HBase exists, where it is used in real-world systems, and how it compares with HDFS and traditional databases.

Students are required to **install, configure, and demonstrate HBase operations live during class**, along with explaining key concepts.

---

## Introduction and Rationale

As organizations began generating massive volumes of data—ranging from web data to user interactions and sensor logs—traditional relational databases (RDBMS) proved inadequate due to their limitations in scalability and flexibility. These systems require predefined schemas, scale vertically (which is expensive), and struggle to efficiently handle billions of rows or sparse datasets.

To address these challenges, Google introduced **BigTable**, a distributed storage system capable of handling large-scale structured data. HBase was later developed as an open-source implementation inspired by BigTable, designed to work on top of Hadoop’s Distributed File System (HDFS).

HBase enables **real-time random read/write access to massive datasets**, something that HDFS alone cannot provide. While HDFS is optimized for high-throughput batch processing and sequential access, it is immutable in nature—once a file is written, it cannot be modified without rewriting it entirely. This limitation makes HDFS unsuitable for applications requiring frequent updates.

In contrast, HBase allows direct modification of data at the row level. For example, updating a single value in HDFS requires rewriting an entire file, whereas in HBase, it can be updated instantly using a simple command. This distinction is critical in understanding the role of HBase in the Hadoop ecosystem.

---

## Real-World Usage of HBase

HBase has been widely used in large-scale enterprise systems where massive datasets and real-time access are required. Companies such as Facebook, Twitter, LinkedIn, and Yahoo have historically used HBase for applications including messaging systems, time-series analytics, and activity tracking.

For example, social media platforms use HBase to manage user activity streams where data is continuously written and queried in real time. Similarly, IoT systems generate constant streams of data that require efficient storage and rapid retrieval, making HBase a suitable choice.

However, it is important to note that while HBase remains relevant, many modern systems are transitioning toward newer distributed databases such as Cassandra, DynamoDB, and cloud-native data warehouses. Despite this shift, HBase remains a **foundational technology** for understanding NoSQL databases and distributed storage concepts.

---

## Key Concepts: HDFS vs HBase

Understanding the difference between HDFS and HBase is essential for this lab.

HDFS is designed for storing large files and performing batch processing. It is immutable, meaning data cannot be modified once written. Any update requires rewriting the entire file.

HBase, on the other hand, is built on top of HDFS and provides a table-like structure that supports real-time read and write operations. It is mutable, allowing individual records to be updated without rewriting the entire dataset.

This distinction makes HBase suitable for applications such as log processing, financial transactions, and user profile updates, where quick access and modification of data are required.

---

## HBase Data Model

HBase uses a column-oriented data model, which differs significantly from traditional row-based relational databases. Data is organized into tables, but instead of fixed columns, it uses **column families**. Each row is identified by a unique row key, and columns can be added dynamically.

For example, a table storing student information may contain a column family called `info`, with columns such as `name` and `grade`. Unlike relational databases, HBase does not require all rows to have the same columns, making it ideal for sparse datasets.

Another important feature is versioning. HBase automatically stores multiple versions of data using timestamps, allowing retrieval of historical values.

---

## Lab Setup Instructions

Students must begin by installing Oracle VirtualBox and downloading the Cloudera QuickStart VM. The VirtualBox version of the VM should be imported using the "Import Appliance" option. While configuring the virtual machine, students should allocate at least 4 GB of RAM and 2 CPU cores, though higher configurations are recommended for performance.

Once the VM is launched, students can log in using the default credentials (`cloudera / cloudera`). After logging in, the Hadoop ecosystem services must be started either through Cloudera Manager or via terminal commands.

To begin working with HBase, students will open the HBase shell using:

```bash
hbase shell
