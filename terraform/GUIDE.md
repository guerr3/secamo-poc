# Terraform Handleiding — Secamo PoC

> **Doelgroep:** Engineer die voor het eerst met Terraform werkt op dit project.
> **Scope:** Alles van AWS-setup tot `terraform apply` voor de `secamo-poc` infrastructuur.

---

## Inhoudsopgave

1. [Wat is Terraform?](#1-wat-is-terraform)
2. [Kernconcepten](#2-kernconcepten)
3. [Onze folderstructuur uitgelegd](#3-onze-folderstructuur-uitgelegd)
4. [Modules in detail](#4-modules-in-detail)
5. [Environments (omgevingen)](#5-environments-omgevingen)
6. [Prerequisite-stappen vóór `terraform init`](#6-prerequisite-stappen-vóór-terraform-init)
7. [Terraform Workflow: init → plan → apply](#7-terraform-workflow-init--plan--apply)
8. [State Management & Locking](#8-state-management--locking)
9. [Veelgemaakte fouten & troubleshooting](#9-veelgemaakte-fouten--troubleshooting)
10. [Cheat Sheet](#10-cheat-sheet)

---

## 1. Wat is Terraform?

Terraform is een **Infrastructure as Code (IaC)** tool van HashiCorp. Je beschrijft je gewenste infrastructuur in `.tf` bestanden (HCL-taal), en Terraform zorgt dat die infrastructuur daadwerkelijk bestaat in AWS.

**Het verschil met handmatig werken:**

| Handmatig (Console)              | Terraform                          |
| -------------------------------- | ---------------------------------- |
| Klik-klik in AWS Console         | Schrijf code, run `apply`          |
| Niemand weet wat er veranderd is | Volledige change history in Git    |
| Moeilijk reproduceerbaar         | Exact dezelfde infra in 1 commando |
| Geen rollback                    | `terraform destroy` of Git revert  |

### Hoe werkt het intern?

```
                    ┌──────────────┐
  .tf bestanden ──► │  terraform   │ ──► AWS API calls
                    │   (engine)   │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │  State File  │  ← Onthoudt wat Terraform
                    │ (.tfstate)   │    heeft aangemaakt
                    └──────────────┘
```

1. **Parse** — Terraform leest alle `.tf` bestanden in de directory
2. **Plan** — Vergelijkt de gewenste staat (je code) met de huidige staat (state file + AWS)
3. **Apply** — Voert alleen de benodigde wijzigingen door via AWS API calls
4. **State update** — Slaat de nieuwe staat op in het state file

---

## 2. Kernconcepten

### Resource

Een resource is één AWS-object. Voorbeelden:

```hcl
resource "aws_instance" "worker" {     # type = aws_instance, naam = worker
  ami           = "ami-0123456789"
  instance_type = "t3.medium"
}
```

### Variable

Input-parameters die je module/configuratie flexibel maken:

```hcl
variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.medium"           # Optioneel: standaardwaarde
}
```

Gebruik in een resource: `instance_type = var.instance_type`

### Output

Waarden die je module "exporteert" zodat andere modules ze kunnen gebruiken:

```hcl
output "instance_id" {
  value = aws_instance.worker.id
}
```

### Data Source

Een **read-only** query naar AWS om bestaande resources op te halen:

```hcl
data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}
# Gebruik: data.aws_ami.al2023.id
```

### Module

Een herbruikbaar pakket van resources. Zie [sectie 4](#4-modules-in-detail).

### Provider

De plugin die Terraform vertelt hoe het met AWS moet praten:

```hcl
provider "aws" {
  region = "eu-west-1"
}
```

### State

Het geheugen van Terraform — een JSON-bestand dat bijhoudt welke resources Terraform beheert en hun huidige configuratie. **Zonder state kan Terraform niets updaten of verwijderen.**

---

## 3. Onze folderstructuur uitgelegd

```
terraform/
├── .gitignore                          ← Voorkomt dat state/secrets in Git komen
│
├── environments/                       ← Omgevings-specifieke configuraties
│   └── poc/                            ← PoC omgeving (hier run je terraform)
│       ├── providers.tf                ← AWS provider + versie constraints
│       ├── backend.tf                  ← Waar het state file wordt opgeslagen
│       ├── variables.tf                ← Alle input variabelen voor deze omgeving
│       ├── main.tf                     ← Module calls (het "wiring diagram")
│       └── outputs.tf                  ← Endpoints en IDs die je nodig hebt
│
├── modules/                            ← Herbruikbare bouwblokken
│   ├── vpc/                            ← Networking (VPC, subnets, NAT)
│   │   ├── main.tf                     ← Resource definities
│   │   ├── variables.tf                ← Input parameters
│   │   └── outputs.tf                  ← Geëxporteerde waarden
│   ├── ingress/                        ← API Gateway + Lambda
│   ├── compute/                        ← EC2 worker instances
│   ├── database/                       ← RDS PostgreSQL
│   ├── storage/                        ← S3 + DynamoDB
│   └── security/                       ← IAM, Security Groups, SSM
│
└── scripts/
    └── worker-startup.sh               ← Bootstrap script voor EC2
```

### Waarom deze structuur?

| Patroon                                                  | Voordeel                                                      |
| -------------------------------------------------------- | ------------------------------------------------------------- |
| `environments/<env>/`                                    | Meerdere omgevingen (poc, staging, prod) met eigen variabelen |
| `modules/<component>/`                                   | Herbruikbaarheid — dezelfde VPC-module voor elke omgeving     |
| Elk module heeft `main.tf`, `variables.tf`, `outputs.tf` | Consistentie — je weet altijd waar je moet kijken             |
| `scripts/` apart                                         | Scheiding van concerns — Terraform config vs. runtime scripts |

### Belangrijk: Waar run je Terraform?

Je voert **altijd** Terraform commando's uit vanuit een **environment directory**, nooit vanuit `modules/` of de root `terraform/` directory:

```bash
cd terraform/environments/poc
terraform init
terraform plan
terraform apply
```

---

## 4. Modules in detail

Een module is simpelweg een directory met `.tf` bestanden die je **aanroept** vanuit je environment.

### Hoe een module werkt

```
environments/poc/main.tf          modules/vpc/
┌─────────────────────────┐       ┌─────────────────────────┐
│ module "vpc" {           │       │ variables.tf            │
│   source = "../modules/ │──────►│   - vpc_cidr            │
│            vpc"          │       │   - availability_zones  │
│   vpc_cidr = "10.0.0.0/ │       │                         │
│              16"         │       │ main.tf                 │
│   availability_zones = [ │       │   - aws_vpc             │
│     "eu-west-1a",        │       │   - aws_subnet (public) │
│     "eu-west-1b"         │       │   - aws_subnet (private)│
│   ]                      │       │   - fck-nat instance    │
│ }                        │       │                         │
│                          │       │ outputs.tf              │
│ # Gebruik output:        │◄──────│   - vpc_id              │
│ module.vpc.vpc_id        │       │   - private_subnet_ids  │
└─────────────────────────┘       └─────────────────────────┘
```

### Data flow tussen modules

In `main.tf` zie je hoe modules aan elkaar gekoppeld zijn:

```hcl
# VPC maakt subnets → Database heeft die subnets nodig
module "database" {
  source             = "../../modules/database"
  private_subnet_ids = module.vpc.private_subnet_ids      # ← output van vpc module
  db_security_group_id = module.security.db_security_group_id  # ← output van security
}
```

Terraform berekent automatisch de **dependency graph**: het weet dat de VPC eerst aangemaakt moet worden vóór de database.

### Onze 6 modules

| Module       | Wat het aanmaakt                           | Waarom apart?                    |
| ------------ | ------------------------------------------ | -------------------------------- |
| **vpc**      | VPC, subnets, IGW, fck-nat, route tables   | Networking is de basis van alles |
| **security** | IAM roles, security groups, SSM parameters | Centraal security-beheer         |
| **database** | RDS PostgreSQL instance, subnet group      | Database-specifieke lifecycle    |
| **compute**  | EC2 instance voor Temporal workers         | Compute apart schaalbaar         |
| **ingress**  | API Gateway HTTP API, Lambda function      | Ingress-layer onafhankelijk      |
| **storage**  | S3 evidence bucket, DynamoDB audit table   | Storage-layer onafhankelijk      |

---

## 5. Environments (omgevingen)

Elke environment is een **volledig onafhankelijke Terraform deployment** met:

- Eigen `backend.tf` → eigen state file
- Eigen `variables.tf` → eigen configuratie (instance sizes, CIDRs, etc.)
- Dezelfde modules, maar met andere parameters

### Huidige opzet

We hebben nu alleen `poc/`. Later kun je toevoegen:

```
environments/
├── poc/          ← t3.medium, db.t4g.small, single-AZ
├── staging/      ← t3.large, db.t4g.medium, multi-AZ
└── prod/         ← t3.xlarge, db.r6g.large, multi-AZ, deletion protection
```

Elke omgeving heeft een **eigen state file** in S3 (key verschilt per env):

```hcl
# poc/backend.tf
terraform {
  backend "s3" {
    key = "environments/poc/terraform.tfstate"    # ← uniek per env
  }
}
```

---

## 6. Prerequisite-stappen vóór `terraform init`

### Stap 0: Installeer Terraform

```powershell
# Windows — via winget
winget install Hashicorp.Terraform

# Verifieer installatie
terraform -version
# Verwacht: Terraform v1.6.x of hoger
```

> **Alternatief:** Download van [terraform.io/downloads](https://developer.hashicorp.com/terraform/downloads) en voeg toe aan je PATH.

### Stap 1: AWS CLI & Credentials configureren

Terraform gebruikt dezelfde credentials als de AWS CLI. Je hebt een **geldig AWS profiel** nodig.

```powershell
# Controleer of je AWS CLI hebt
aws --version

# Controleer of je credentials werken
aws sts get-caller-identity
```

**Als je SSO/Identity Center gebruikt** (zoals bij jullie setup met session tokens):

```powershell
# Optie A: Gebruik het juiste profiel expliciet
$env:AWS_PROFILE = "760659115776_PowerUser-IAMFullAccess"
aws sts get-caller-identity

# Optie B: Login via SSO (als geconfigureerd)
aws sso login --profile 760659115776_PowerUser-IAMFullAccess
```

> ⚠️ **Session tokens verlopen!** Als je een `InvalidClientTokenId` error krijgt, moet je je session token vernieuwen via AWS SSO / Identity Center.

**Verifieer dat het werkt:**

```powershell
aws sts get-caller-identity --profile 760659115776_PowerUser-IAMFullAccess
# Verwacht output:
# {
#     "UserId": "...",
#     "Account": "760659115776",
#     "Arn": "arn:aws:sts::760659115776:assumed-role/..."
# }
```

### Stap 2: S3 State Bucket aanmaken

Terraform slaat zijn state op in S3. Deze bucket moet **vóór** `terraform init` bestaan.

```powershell
# Stel je profiel in
$env:AWS_PROFILE = "760659115776_PowerUser-IAMFullAccess"

# Maak de S3 bucket
aws s3api create-bucket `
  --bucket "secamo-poc-tfstate-760659115776" `
  --region eu-west-1 `
  --create-bucket-configuration LocationConstraint=eu-west-1

# Activeer versioning (beschermt tegen corrupte state)
aws s3api put-bucket-versioning `
  --bucket "secamo-poc-tfstate-760659115776" `
  --versioning-configuration Status=Enabled

# Activeer encryption
aws s3api put-bucket-encryption `
  --bucket "secamo-poc-tfstate-760659115776" `
  --server-side-encryption-configuration '{
    "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}, "BucketKeyEnabled": true}]
  }'

# Blokkeer publieke toegang
aws s3api put-public-access-block `
  --bucket "secamo-poc-tfstate-760659115776" `
  --public-access-block-configuration '{
    "BlockPublicAcls": true,
    "IgnorePublicAcls": true,
    "BlockPublicPolicy": true,
    "RestrictPublicBuckets": true
  }'
```

### Stap 3: DynamoDB Lock Table aanmaken

State locking voorkomt dat twee engineers tegelijk `terraform apply` draaien en de state corrumperen.

```powershell
aws dynamodb create-table `
  --table-name "secamo-poc-tfstate-lock" `
  --attribute-definitions AttributeName=LockID,AttributeType=S `
  --key-schema AttributeName=LockID,KeyType=HASH `
  --billing-mode PAY_PER_REQUEST `
  --region eu-west-1
```

### Stap 4: Update `backend.tf` met je bucket naam

Het bucket-naam in `backend.tf` moet overeenkomen met wat je zojuist hebt aangemaakt:

```hcl
# terraform/environments/poc/backend.tf
terraform {
  backend "s3" {
    bucket         = "secamo-poc-tfstate-760659115776"   # ← jouw bucket naam
    key            = "environments/poc/terraform.tfstate"
    region         = "eu-west-1"
    encrypt        = true
    dynamodb_table = "secamo-poc-tfstate-lock"
  }
}
```

### Stap 5: Lambda placeholder aanmaken

De ingress-module verwacht een zip-bestand als Lambda deployment package. Maak een minimale placeholder:

```powershell
cd c:\Users\ghost\Documents\codebases\secamo-poc\terraform\modules\ingress

# Maak een minimale Python handler
@"
def handler(event, context):
    return {
        "statusCode": 200,
        "body": '{"status": "placeholder"}'
    }
"@ | Out-File -Encoding utf8 handler.py

# Zip het bestand
Compress-Archive -Path handler.py -DestinationPath placeholder.zip -Force

# Ruim de losse handler op
Remove-Item handler.py
```

### Stap 6: Environment variabelen instellen voor Terraform

```powershell
# Zorg dat Terraform het juiste AWS profiel gebruikt
$env:AWS_PROFILE = "760659115776_PowerUser-IAMFullAccess"

# OF stel de regio expliciet in
$env:AWS_DEFAULT_REGION = "eu-west-1"
```

### Checklist vóór `terraform init`

- [ ] Terraform geïnstalleerd (`terraform -version` werkt)
- [ ] AWS credentials geldig (`aws sts get-caller-identity` slaagt)
- [ ] S3 state bucket aangemaakt met versioning + encryption
- [ ] DynamoDB lock table aangemaakt
- [ ] `backend.tf` bijgewerkt met je bucket naam
- [ ] `placeholder.zip` aanwezig in `modules/ingress/`
- [ ] `AWS_PROFILE` environment variable gezet

---

## 7. Terraform Workflow: init → plan → apply

### Altijd vanuit de environment directory

```powershell
cd c:\Users\ghost\Documents\codebases\secamo-poc\terraform\environments\poc
```

### `terraform init` — Initialisatie

Downloadt providers, initialiseert de backend, en bereidt modules voor:

```powershell
terraform init
```

**Wat er gebeurt:**

- Downloadt de `aws` en `random` providers naar `.terraform/`
- Verbindt met de S3 backend
- Valideert alle module references

**Verwachte output:**

```
Initializing the backend...
Initializing provider plugins...
- Finding hashicorp/aws versions matching "~> 5.40"...
- Installing hashicorp/aws v5.40.x...
Terraform has been successfully initialized!
```

### `terraform plan` — Dry run

Laat zien wat Terraform **zou doen** zonder iets te veranderen:

```powershell
terraform plan
```

**Output interpretatie:**

```
  + aws_vpc.main                    # + = wordt aangemaakt (groen)
  ~ aws_instance.worker             # ~ = wordt gewijzigd (geel)
  - aws_s3_bucket.old               # - = wordt verwijderd (rood)

Plan: 23 to add, 0 to change, 0 to destroy.
```

> 💡 **Tip:** Sla het plan op voor audit trail:
>
> ```powershell
> terraform plan -out=tfplan
> ```

### `terraform apply` — Uitvoeren

Past de wijzigingen echt toe in AWS:

```powershell
terraform apply

# Of met een opgeslagen plan (skip confirmation prompt):
terraform apply tfplan
```

Terraform vraagt altijd om bevestiging. Typ `yes` om door te gaan.

### `terraform destroy` — Alles opruimen

Verwijdert **alle** resources die door Terraform zijn aangemaakt:

```powershell
terraform destroy
```

> ⚠️ **Gebruik met grote voorzichtigheid!** Dit verwijdert je database, EC2 instances, etc.

### Samenvatting van het workflow

```
  terraform init          Eenmalig bij eerste setup of na backend wijziging
       │
       ▼
  terraform plan          Altijd vóór apply — bekijk wat er gaat veranderen
       │
       ▼
  terraform apply         Voer de wijzigingen door
       │
       ▼
  terraform output        Bekijk endpoints, IDs, etc. na apply
```

---

## 8. State Management & Locking

### Wat is het state file?

Een JSON-bestand dat Terraform's "geheugen" is. Het bevat:

- Welke resources Terraform beheert
- Hun huidige configuratie
- Metadata (resource IDs, ARNs, etc.)

### Waarom remote state (S3)?

| Local state                  | Remote state (S3)                    |
| ---------------------------- | ------------------------------------ |
| Alleen op jouw machine       | Gedeeld met het team                 |
| Geen locking                 | DynamoDB locking voorkomt conflicten |
| Risico op verlies            | Versioned met rollback mogelijkheid  |
| Secrets in plaintext op disk | Encrypted at rest in S3              |

### Hoe locking werkt

```
  Engineer A: terraform apply          Engineer B: terraform apply
       │                                     │
       ▼                                     ▼
  Lock DynamoDB ✅                      Lock DynamoDB ❌
       │                                     │
       ▼                                     ▼
  Apply changes                         "Error: state locked"
       │                                (wacht tot A klaar is)
       ▼
  Unlock DynamoDB ✅
```

### State commando's

```powershell
# Bekijk alle resources in state
terraform state list

# Bekijk details van één resource
terraform state show module.vpc.aws_vpc.main

# Verwijder een resource uit state (NIET uit AWS)
terraform state rm module.storage.aws_s3_bucket.evidence

# Importeer een bestaande AWS resource in state
terraform import module.vpc.aws_vpc.main vpc-0abc123def
```

---

## 9. Veelgemaakte fouten & troubleshooting

### `Error: No valid credential sources found`

**Oorzaak:** AWS credentials niet geconfigureerd of verlopen.

```powershell
# Fix: Stel het profiel in
$env:AWS_PROFILE = "760659115776_PowerUser-IAMFullAccess"
AWS_PROFILE=PowerUser-IAMFullAccess-760659115776
# Als session token verlopen is, vernieuw via SSO:
aws sso login --profile PowerUser-IAMFullAccess-760659115776
```

PowerUser-IAMFullAccess-760659115776

### `Error: Failed to get existing workspaces: S3 bucket does not exist`

**Oorzaak:** De S3 state bucket is nog niet aangemaakt.

```powershell
# Fix: Volg Stap 2 uit sectie 6
```

### `Error: Error acquiring the state lock`

**Oorzaak:** Een eerdere `terraform apply` is gecrasht en heeft de lock niet vrijgegeven.

```powershell
# Fix: Forceer unlock (gebruik het Lock ID uit de error message)
terraform force-unlock <LOCK_ID>
```

### `Error: Unsupported Terraform Core version`

**Oorzaak:** Je Terraform versie is te oud.

```powershell
# Fix: Update Terraform
winget upgrade Hashicorp.Terraform
```

### `Error: Module not found`

**Oorzaak:** De `source` path in je module call klopt niet.

```powershell
# Controleer of het pad klopt relatief aan je environment directory:
# environments/poc/main.tf → ../../modules/vpc = terraform/modules/vpc ✓
```

### `Error: Reference to undeclared resource`

**Oorzaak:** Je verwijst naar een resource `output` die niet bestaat in de module.

```powershell
# Fix: Controleer outputs.tf van de betreffende module
# Voorbeeld: module.vpc.vpc_id → check modules/vpc/outputs.tf
```

### Algemene debug tips

```powershell
# Verbose logging aanzetten
$env:TF_LOG = "DEBUG"
terraform plan

# Logging uitzetten
Remove-Item Env:\TF_LOG

# Format-check je .tf bestanden
terraform fmt -recursive

# Valideer syntax zonder plan
terraform validate
```

---

## 10. Cheat Sheet

```powershell
# ── Setup ────────────────────────────────────────────────────
$env:AWS_PROFILE = "760659115776_PowerUser-IAMFullAccess"
cd c:\Users\ghost\Documents\codebases\secamo-poc\terraform\environments\poc

# ── Standaard workflow ───────────────────────────────────────
terraform init                        # Eenmalig / na backend change
terraform fmt -recursive ../../       # Format alle .tf bestanden
terraform validate                    # Check syntax
terraform plan                        # Dry run
terraform apply                       # Deploy
terraform output                      # Bekijk resultaten

# ── Informatie ───────────────────────────────────────────────
terraform state list                  # Alle resources
terraform state show <resource>       # Detail van 1 resource
terraform providers                   # Geïnstalleerde providers
terraform graph | dot -Tpng > graph.png  # Dependency graph

# ── Onderhoud ────────────────────────────────────────────────
terraform plan -destroy               # Preview van destroy
terraform destroy                     # Alles verwijderen
terraform force-unlock <ID>           # Lock vrijgeven na crash

# ── Targeting (1 resource bijwerken) ─────────────────────────
terraform plan -target=module.compute
terraform apply -target=module.compute
```

---

## Architectuur Overzicht

```
                    Internet
                       │
              ┌────────▼─────────┐
              │  API Gateway     │  ← HTTP API (pay-per-request)
              │  /api/v1/ingress │
              └────────┬─────────┘
                       │
              ┌────────▼─────────┐
              │  Lambda (Python) │  ← Ingress handler (ARM64)
              │  256MB / 30s     │
              └────────┬─────────┘
                       │
    ┌──────────────────┼──────────────────────┐
    │         VPC 10.0.0.0/16                 │
    │                  │                      │
    │  ┌───────────────┼───────────────┐      │
    │  │ Public Subnet (10.0.0.0/24)  │      │
    │  │  ┌─────────────────────┐     │      │
    │  │  │ fck-nat (t4g.nano)  │     │      │
    │  │  └────────┬────────────┘     │      │
    │  └───────────┼──────────────────┘      │
    │              │                          │
    │  ┌───────────┼──────────────────┐      │
    │  │ Private Subnet (10.0.100/24) │      │
    │  │                              │      │
    │  │  ┌────────────────────────┐  │      │
    │  │  │ EC2 Worker (t3.medium) │  │      │
    │  │  │   ┌─── Temporal ───┐  │  │      │
    │  │  │   │ iam-graph      │  │  │      │
    │  │  │   │ soc-defender   │  │  │      │
    │  │  │   │ audit          │  │  │      │
    │  │  │   └────────────────┘  │  │      │
    │  │  └───────────┬───────────┘  │      │
    │  │              │              │      │
    │  │  ┌───────────▼───────────┐  │      │
    │  │  │ RDS PostgreSQL       │  │      │
    │  │  │ (db.t4g.small)       │  │      │
    │  │  └──────────────────────┘  │      │
    │  └─────────────────────────────┘      │
    └───────────────────────────────────────┘

    S3: Evidence storage          DynamoDB: Audit logs
    SSM: Tenant secrets           CloudWatch: Logging
```

---

> **Volgende stap:** Voer de [prerequisite-checklist](#checklist-vóór-terraform-init) uit en run `terraform init` vanuit `terraform/environments/poc/`.
