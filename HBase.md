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

# Setup Instructions: Cloudera VM and HBase Configuration

This section provides detailed, step-by-step instructions for installing Oracle VirtualBox, downloading and setting up the Cloudera QuickStart VM, and configuring HBase. Students must follow all steps carefully to ensure a working environment for the lab and classroom demonstration.

---

## Step 1: Install Oracle VirtualBox

Begin by downloading Oracle VirtualBox from the official website:

https://www.virtualbox.org/wiki/Downloads

Select the appropriate version for your operating system (Windows, macOS, or Linux). Install the software using the default settings. During installation, network interfaces may briefly reset—this is normal.

Once installed, launch VirtualBox to ensure it is working correctly.

---

## Step 2: Download Cloudera QuickStart VM

Next, download the Cloudera QuickStart Virtual Machine. This VM contains Hadoop, HDFS, HBase, and other ecosystem tools pre-configured.

Download from:

https://www.cloudera.com/downloads/quickstart_vms.html

Choose:
- **Cloudera QuickStart VM for VirtualBox**

The downloaded file will typically be in `.zip` or `.ova` format and may be large (several GB), so ensure a stable internet connection.

After downloading:
- If the file is zipped, extract it to obtain the `.ova` file.

---

## Step 3: Import VM into VirtualBox

Open Oracle VirtualBox and import the downloaded appliance:

1. Click **File → Import Appliance**
2. Select the `.ova` file you downloaded
3. Click **Next**

Before importing, adjust the system settings:
- RAM: Minimum **4 GB** (Recommended: 8 GB)
- CPU: Minimum **2 cores**

Click **Import** and wait for the process to complete.

---

## Step 4: Configure Virtual Machine Settings (Important)

Before starting the VM, adjust the following:

### System Settings
- Go to **Settings → System**
- Ensure:
  - RAM is at least 4096 MB
  - Processor cores are set to 2 or more

### Display Settings
- Go to **Settings → Display**
- Set Video Memory to maximum (128 MB)

### Network Settings (Optional but recommended)
- Use **NAT** for basic connectivity
- Use **Bridged Adapter** if network access is required externally

---

## Step 5: Start the Cloudera VM

Click **Start** to boot the virtual machine.

Once loaded, log in using:
