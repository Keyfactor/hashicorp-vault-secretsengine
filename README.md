# Hashicorp Vault Secrets Engine

Keyfactor enables DevOps teams to get seamless access to trusted internal and public certificates via native Vault API
calls and commands, while security teams maintain complete visibility and control over backend PKI operations.

## About the Hashicorp Vault Secrets Engine plugin by Keyfactor

The Keyfactor Secrets Engine provides a PKI backend for Vault to issue trusted certificates via the Keyfactor platform. It enables developers to use native Vault API calls and
commands to request certificates from Keyfactor and allows security teams to maintain visibility and control over all certificates issued to Vault instances.
This plugin connects Vault with trusted public, private, or cloud-hosted CAs configured in the Keyfactor platform.
Certificates are requested through Vault using standard Vault commands, and are then redirected to Keyfactor so that the certificates can be issued off of a trusted enterprise
certificate authority. After issuance, the certificate is then returned to Hashicorp Vault and stored within the Vault Secrets store to then be used in other applications.

---

## Overview

The Keyfactor Secrets Engine for Hashicorp Vault is a Vault plugin that replicates Vault’s onboard PKI API and processes certificate enrollment requests through the Keyfactor Command or Keyfactor Control platform. In many cases the onboard PKI engine included with Vault can be swapped for the Keyfactor engine seamlessly, with no impact to Vault client applications. While the simplicity of the onboard PKI is attractive to developers who are trying to implement the simplest solution in order to meet encryption requirements, it presents other enterprise teams with some challenges when it comes to PKI operations and security:

- The Vault infrastructure and root materials are not managed by PKI professionals and policies, but rather by DevOps teams that may not be trained in how to properly handle and manage an enterprise PKI.
- Lack of Certificate Lifecycle Management places organizations in a reactionary posture. If there are weaknesses in the organization processes, full visibility of the certificates is necessary in order to identify these risks prior to a security event or audit failure.
- All certificates are susceptible as an attack surface and should be managed and monitored, regardless of their lifetime, to ensure that issuance policies and certificate standards are followed.

Keyfactor Command can provide the control and visibility needed for a Vault environment. Using the Keyfactor Secrets Engine plugin for Vault, PKI functionality is directed to your enterprise PKI environment, placing control back into the hands of the enterprise PKI admins, and allowing your PKI admins to stay in control of how and when certificates are issued. The Keyfactor Secrets Engine offers the following enterprise capabilities:

- Issue certificates and place them into the Vault secrets store using your existing enterprise PKI.
- Eliminate the need for a standalone PKI within the vault environment.
- Gain complete visibility and management of certificates across all Vault instances and manage them through a single pane of glass.
- Reporting, alerting, automation, and auditing on the certificates within the environment.
- Easily identify and revoke non-compliant or rogue certificates.
- Integrate with SIEMs and ticketing systems for automated notifications.

    !["high-level-architecture"](images/arch-diagram.png)

## Compatibility

This Vault Plugin has been tested against Hashicorp Vault version 1.10.0 and the Keyfactor Platform 9.6+.  We provide several pre-built binaries that correspond to various operating systems and processor architectures.  If not building the plugin from source code, select the os/architecture combination that corresponds to your environment.

## Installation

### Requirements

The requirements for the plugin are relatively simple. It runs as a single executable on the Hashicorp Vault server.
There are no specific system requirements to install it, however there are a few general things that must be in place for
it to function properly. These requirements are listed below, and are then expanded in the details throughout this
document.

1. **General Keyfactor Requirements**
    - A functional instance of Keyfactor Command
    - An administrative user account to be used for configuring the Keyfactor options needed for the implementation
    - A functional integrated certificate authority to be used for issuing the certificates
    - A certificate template (or templates) defined to use for certificate issuance.
    - A user account with permissions to connect to the Keyfactor API and submit certificate requests. This user account will require READ and ENROLL permissions on the certificate template that you will use for the Vault plugin.

2. **General Hashicorp Vault Requirements**
    - A functional Hashicorp Vault Installation
    - An administrative account with permission to login to the Hashicorp Vault server in order to make administrative changes.
    - An adequate number of unseal keys to meet the minimum criteria to unseal the Hashicorp Vault
    - A Hashicorp Vault login token

### Setup - Keyfactor

1. **Create the Active Directory service account**

    For the purposes of this document, we will not go into the details of how to create an Active Directory user since this process varies widely by company, however, here are a couple things to consider:

    - Ensure that the user does not have an expiring password, or if it does, ensure that the password resets are managed carefully. Expiration of this password could result in production outages with the plugin.
    - Ensure that the user does not have logon time restrictions unless you only want the Hashicorp Vault plugin to function during specific timeframes.

1. **Assign the user permissions in Keyfactor Command**

    In order to be able to enroll for certificates through the Keyfactor Command API, it will be necessary to create the necessary role and delegate permissions within Keyfactor. It is not a requirement that this be a new role. If there is an existing role within your organization that allows for these basic permissions, that role can be used for this connection. If you do not have an existing role, and would like to create one, those steps are described later in this document.

1. **Create the certificate template to use**

    The first step to configuring Keyfactor is to create the certificate template that will be used for the enrollment and publish it into Keyfactor.

**To create a new certificate template and import into Keyfactor:**

1. Open up the Certificate Authority MMC console.

1. Right Click on Certificate Templates, and select "Manage". This will open up the Certifcate Templates MMC
console.

1. In the Certificate Templates MMC console, choose a template that you would like to use as a starting point for
your new Vault Plugin template, and duplicate it as a starting point. For standard SSL certificates, most companies will start with a template such as "Web Server" for a general template. In situations where you
need the certificate to do mutual TLS authentication, you may wish to choose the Computer template so that it will include both the Client Authentication and Server Authentication key usages. To duplicate the template, right click on the template and select "Duplicate Template".

1. You should now see the properties for the new template you are creating, and you will need to customize the
template for use with the plugin. In most cases, there will be only a few minor changes that need made to the
template.

    1. On the General tab, change the Template Display Name to represent the name that you want to have on the template.

        !["template1"](images/template1.png)

    1. On the General tab, set the Validity Period and Renewal Period for the certificates that you are going to issue off of this template.

        !["template2"](images/template2.png)

    > Validity and Renewal period values depend on use case and organizational policy.

    1. On the Request Handling tab, ensure that the option is selected for "Allow Private Keys to be Exported"

        !["template3"](images/template3.png)

    1. Unless you are planning to implement an approval workflow process for the certificates issued through Hashicorp Vault, ensure that "CA Certificate Manager Approval" is not checked on the Issuance Requirements tab.

        !["template4"](images/template4.png)

    1. On the Security tab, add the service account that was created earlier so that it has permissions to enroll certificates off of this template. Click Add to search for the user to add, and then grant the user READ and ENROLL permissions on the Template.

        !["template5"](images/template5.png)

    1. Click OK to save the template.

1. **Publish the template on the Certificate Authority**
    It is now necessary to take the certificate template that you created and publish it so that it is an available template for issuance off of the CA.

    To publish the template:

    1. Open the Certificate Authority MMC console
    1. Right on Certificate Templates in the left hand pane and select NEW – Certificate Template to Issue
    !["template6"](images/template6.png)

    1. Select the template that was created in the previous step, and then click OK.
    !["template6"](images/template7.png)

    1. Import the new template into the Keyfactor console.
    Now that the new certificate template has been created on the CA, we need to ensure that the template is available for
issuance within the Keyfactor Command console.

    **To import the certificate template:**

    1. Log into the Keyfactor Command console as a user with administrative privileges
    1. Select PKI Management from the top menu bar, then select "Certificate Templates"
