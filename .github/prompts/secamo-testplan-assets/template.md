# Titelpagina
[Logo Secamo]

Testplan - Modulaire Process Orchestrator

Onderdeel van stage AP Hogeschool - Secamo - Warre Gehre - Toegepaste Informatica (Cybersecurity) - Begeleider/Mentor: Xander Boedt - Academiejaar 2025-2026

# Inhoud
- [Titelpagina](#titelpagina)
- [Inhoud](#inhoud)
- [Versiebeheer](#versiebeheer)
- [Termen en afkortingen](#termen-en-afkortingen)
- [Inleiding](#inleiding)
- [Projectbeschrijving en scope](#projectbeschrijving-en-scope)
- [Belanghebbenden](#belanghebbenden)
- [Risicoanalyse](#risicoanalyse)
- [Teststrategie](#teststrategie)
- [Testomgeving](#testomgeving)
- [Bronvermelding](#bronvermelding)

# Versiebeheer
| Nr. | Datum | Verspreiding | Wijziging |
|---|---|---|---|
| 0.1 | 2026-03-20 | Intern - Warre Gehre | Eerste werkversie van het testplan op basis van Blueprint en projectscope. |
| 0.2 | 2026-03-24 | Intern - Warre Gehre, Xander Boedt | Inleiding, projectbeschrijving, belanghebbenden en risicoanalyse toegevoegd. |
| 0.3 | 2026-03-27 | Intern - Warre Gehre, Xander Boedt | Teststrategie, testomgeving en bronvermelding uitgewerkt en gealigneerd met codebase. |
| 1.0 | 2026-03-27 | AP Hogeschool - Secamo | Finale versie voor indiening en evaluatie. |

# Termen en afkortingen
| Term | Omschrijving |
|---|---|
| Adapterlaag | Integratielaag die externe systemen afschermt van de interne orchestratielogica. |
| API | Application Programming Interface: koppelvlak waarmee systemen data of functionaliteit uitwisselen. |
| AWS | Amazon Web Services: cloudplatform waarop de infrastructuur en services van de PoC draaien. |
| DynamoDB | NoSQL-databankdienst van AWS, gebruikt voor onder meer audit- en tokenopslag. |
| HITL | Human-in-the-Loop: goedkeuringsstap waarbij een menselijke operator beslist over kritieke acties. |
| IAM | Identity and Access Management: beheer van identiteiten, rollen en toegangsrechten. |
| IaC | Infrastructure as Code: infrastructuurbeheer via code en declaratieve configuratie (bv. Terraform). |
| Ingress | Inkomende verwerkingslaag die externe requests ontvangt, valideert en doorstuurt. |
| OCSF | Open Cybersecurity Schema Framework: standaard voor normalisatie van security-events. |
| PoC | Proof of Concept: afgebakende implementatie om haalbaarheid en waarde van een oplossing aan te tonen. |
| PII | Personally Identifiable Information: persoonsgegevens die direct of indirect een persoon identificeren. |
| S3 | Amazon Simple Storage Service: objectopslagdienst van AWS voor evidence en documenten. |
| SSM Parameter Store | AWS-dienst voor veilige opslag van configuratie en secrets. |
| Temporal | Workflow orchestration platform voor betrouwbare, langlopende en herstartbare procesuitvoering. |
| Tenant | Afgescheiden klantcontext binnen een multi-tenantarchitectuur. |

# Inleiding

Dit testplan is bedoeld voor de projectstakeholders van het Secamo-stageproject: de student (Warre Gehre), de stagebegeleiders, technische reviewers en beslissingsnemers die de kwaliteit en vrijgave van het platform beoordelen. Het document biedt een gedeeld kader om testbeslissingen te motiveren, testresultaten eenduidig te interpreteren en risico's transparant op te volgen.

Voor de modulaire process orchestrator is een projectspecifiek testplan essentieel omdat het systeem meerdere kritieke lagen combineert: ingress via AWS API Gateway/Lambda, orkestratie via Temporal-workflows en activiteiten, en integraties met cloud- en securitydiensten via een adapterpatroon. Fouten in routering, tenant-isolatie, retry-gedrag of contractvalidatie kunnen rechtstreeks leiden tot operationele impact, beveiligingsrisico's of onbetrouwbare verwerking. Dit plan vertaalt daarom de architecturale keuzes en kwaliteitsdoelen uit de Blueprint naar concrete en meetbare testaanpak, scope en acceptatiecriteria.

Wat je in dit document mag verwachten: dit document beschrijft de testscope, testtypes, omgevingsvereisten, risico-inschatting, planning en verantwoordelijkheden voor het Secamo-platform. Daarnaast licht het toe hoe testresultaten worden beoordeeld tegenover de vooropgestelde kwaliteitsdoelen en welke beslisregels gelden voor vrijgave. De opbouw sluit aan op de technische en organisatorische context uit de Blueprint, zodat ontwerpkeuzes en teststrategie consistent blijven.

Conclusie: dit testplan is het formele instrument om de Blueprint gecontroleerd om te zetten naar aantoonbaar betrouwbare en veilige oplevering.

# Projectbeschrijving en scope
Dit project realiseert voor Secamo een modulaire process orchestrator die repetitieve cloud- en securityprocessen centraliseert en automatiseert. De aanleiding is de huidige operationele belasting door manuele taken zoals user lifecycle-acties, alertverwerking en compliance-opvolging, gecombineerd met beperkte autonomie bij eerder extern gebouwde automatisatie. De beoogde situatie is een intern onderhoudbaar platform dat schaalbaar, auditeerbaar en tenant-gescheiden werkt, zodat Secamo als Trusted Advisor sneller en consistenter kan leveren.

De functionele scope van deze PoC omvat: 
- Een Temporal-gebaseerde orchestration engine voor duurzame workflow-uitvoering.
- Een ingress-laag via API Gateway en Lambda voor validatie en routering van externe triggers. 
- Een adapterlaag voor veilige, tenant-specifieke integraties met onder meer Microsoft Graph, Defender en Jira. 
- Een Human-in-the-Loop-flow via Microsoft Teams Adaptive Cards voor kritieke beslissingen.
- Een audit- en evidencepad met centrale opslag in DynamoDB en S3. 
- Daarnaast behoort de opzet van de vereiste AWS-infrastructuur via IaC (Terraform) tot de scope.

Concreet automatiseert deze PoC drie soorten processen:
1. User lifecycle requests
2. Alertverwerking en incidentmanagement
3. Periodieke compliance reporting

Niet binnen deze scope: 
- High-availability-uitrol 
- Migratie van bestaande Step Functions
- Extra legacy-integraties
- Langetermijn operationele support.

# Belanghebbenden
| Naam | Bijdrage |
| --- | --- |
| Warre Gehre | Analyse, ontwerp, implementatie, testuitvoering, documentatie en projectopvolging als uitvoerder van de PoC. |
| Xander Boedt (Secamo) | Sponsor en primaire opdrachtgever: scopevalidatie, technische review, gate-goedkeuring, nalezen van tussentijdse opleveringen en inhoudelijke evaluatie van operationele bruikbaarheid voor SOC-opvolging. |
| Secamo Cybersecurity Strategy Analist (Maxim) | Extra tester: valideert de strategische relevantie van compliancerelateerde flows en geeft feedback op toepasbaarheid binnen securitystrategie-operaties. |
| Secamo Cybersecurity Engineer (Dustin) | Extra tester: test alert- en incidentflows en Human-in-the-Loop-interacties, verifieert triage-werkbaarheid en levert technische feedback op security-automatisatie. |
| AP-begeleiding en schooljury | Nalezen en beoordeling van de academische kwaliteit, methodologische onderbouwing en projectresultaten. |

In de eerste fase van het project ligt de focus op de samenwerking tussen Warre en Xander, waarbij Xander als primaire technische reviewer en gatekeeper fungeert. In latere fasen kunnen de extra testers (Maxim en Dustin) meer betrokken worden bij specifieke testcases die relevant zijn voor hun expertisegebieden.


# Risicoanalyse
Deze risicoanalyse behandelt uitsluitend risico's die eigen zijn aan de werking van de modulaire process orchestrator binnen de Secamo-context. De inventaris is afgeleid uit de Blueprint (functionele scope, use-cases, business rules en technisch design). Meta-risico's zoals ziekte, planning, internetuitval of algemene stage-omstandigheden zijn bewust uitgesloten.

Voor de berekening van prioriteit wordt de volgende formule gebruikt:
**Prior. = rnd((1/5) x risico x impact)**

## Schaal risico (kans)
| Risico | Betekenis |
|---|---|
| 0 | Kan nooit optreden |
| 1 | Heel erg kleine kans |
| 2 | Matige kans |
| 3 | Grote kans |
| 4 | Erg grote kans |
| 5 | Gedurende de levensduur van de applicatie zal de gebeurtenis quasi zeker minstens eenmaal plaatsvinden |

## Schaal impact
| Risico | Betekenis |
|---|---|
| 0 | Geen effect, ook niet op lange termijn, noch voor de eindgebruiker als de eigenaar van de applicatie |
| 1 | De impact voor de eindgebruiker is minimaal of van zeer korte duur of situeert zich achter de schermen met op langere termijn invloed op herbruikbaarheid of onderhoudbaarheid |
| 2 | Een aantal functionaliteiten zijn tijdelijk niet beschikbaar voor de eindgebruiker |
| 3 | Een belangrijk deel van de functionaliteiten van de applicatie is tijdelijk niet beschikbaar |
| 4 | De meeste functionaliteit van de applicatie is verloren maar een aantal problemen kan tijdelijk overbrugd worden |
| 5 | Geen enkele functionaliteit van de applicatie is beschikbaar |

## Geprioriteerde risico's
### R1 - Over-permissieve IAM-rollen met cross-tenant toegang (Testrelevantie: H)
| Omschrijving | Risico | Impact | Prior. |
|---|:---:|:---:|:---:|
| IAM-rollen voor workers en activities kunnen SSM-paden of S3-buckets benaderen buiten /secamo/tenants/{tenant_id}/..., waardoor een tenant bij secrets of evidence van andere tenants kan. | 4 | 5 | 4 |

| Actie | Actietype |
|---|---|
| Least-privilege IAM afdwingen met tenant-scoped resource policies, deny-by-default op niet-tenant resources en periodieke policy-audits met negatieve autorisatietests. | Inperken |

### R2 - Onbeschikbaarheid connectors breekt kernflows (Testrelevantie: H)
| Omschrijving | Risico | Impact | Prior. |
|---|:---:|:---:|:---:|
| Uitval of throttling van Microsoft Graph, Jira of andere connectors via de registry zorgt ervoor dat IAM-onboarding, alert-enrichment en ticketing-workflows falen of blijven hangen. | 5 | 4 | 4 |

| Actie | Actietype |
|---|---|
| Connectorfouten gecontroleerd afhandelen met retry/backoff, timeout-grenzen, circuit-breaker patroon en fallbackstatussen in workflows. | Inperken |

### R3 - Foutieve tenant-routing en queue-mixing (Testrelevantie: H)
| Omschrijving | Risico | Impact | Prior. |
|---|:---:|:---:|:---:|
| Een bug in shared.routing of ingress-pipeline kan events met een verkeerd tenant_id naar de verkeerde Temporal task queue sturen, waardoor workflows onder een andere tenant-context draaien. | 3 | 5 | 3 |

| Actie | Actietype |
|---|---|
| Routingcontracten hard valideren, route-matrix regressietesten voorzien en tenant-id als verplicht invariant in elke verwerkingsstap controleren. | Inperken |

### R4 - Lambda-authorizer bypass of misconfiguratie (Testrelevantie: H)
| Omschrijving | Risico | Impact | Prior. |
|---|:---:|:---:|:---:|
| Verkeerde configuratie van de L1 authorizer kan ertoe leiden dat requests zonder correcte tenant-header of provider-authenticatie toch bij de ingress-Lambda en workflows terechtkomen. | 3 | 5 | 3 |

| Actie | Actietype |
|---|---|
| Authorizerconfiguratie versioneren en valideren met negatieve toegangstesten, inclusief verplichting van tenant-header en provider-authenticatie per route. | Inperken |

### R5 - Niet-deterministische workflow-logica (Testrelevantie: H)
| Omschrijving | Risico | Impact | Prior. |
|---|:---:|:---:|:---:|
| Workflows in workflows/*.py kunnen per ongeluk niet-deterministische constructies bevatten, wat bij replay tot failures en stuck executions leidt. | 3 | 4 | 2 |

| Actie | Actietype |
|---|---|
| Workflowrichtlijnen voor determinisme afdwingen, replay-tests standaard opnemen en wijzigingen in workflowcode laten controleren via gerichte review checklist. | Inperken |

### R6 - Race conditions in signals en timers (Testrelevantie: H)
| Omschrijving | Risico | Impact | Prior. |
|---|:---:|:---:|:---:|
| Workflows zoals GraphSubscriptionManagerWorkflow en HiTL-gerelateerde child-workflows gebruiken timers en signals, waarbij slechte ordening of ontbrekende guards kan leiden tot gemiste signals of dubbele paden. | 3 | 3 | 2 |

| Actie | Actietype |
|---|---|
| Concurrency-scenario's expliciet testen, guards op state-overgangen invoeren en idempotente signal-handlers afdwingen. | Inperken |

### R7 - HiTL-token TTL verloopt voor menselijke actie (Testrelevantie: H)
| Omschrijving | Risico | Impact | Prior. |
|---|:---:|:---:|:---:|
| HiTL-approvals gebruiken DynamoDB-TTL voor tokens; een te korte TTL of clock-skew kan maken dat een analist niet meer kan antwoorden en kritieke incidentacties nooit worden uitgevoerd. | 4 | 3 | 2 |

| Actie | Actietype |
|---|---|
| TTL-waarden kalibreren met operationele responstijden, clock-skew compenseren en fallback-escalatie voorzien bij verlopen tokens. | Inperken |

### R8 - Meervoudige of herhaalde HiTL-callbacks (Testrelevantie: H)
| Omschrijving | Risico | Impact | Prior. |
|---|:---:|:---:|:---:|
| Een token kan meerdere keren gebruikt worden, waardoor dezelfde HiTLApprovalWorkflow meerdere keren een beslissingspad triggert. | 3 | 4 | 2 |

| Actie | Actietype |
|---|---|
| Single-use tokensemantiek afdwingen, callback-idempotentie implementeren en duplicate-callback detectie met auditlogging toevoegen. | Inperken |

### R9 - OCSF-schema-evolutie breekt normalisatie (Testrelevantie: H)
| Omschrijving | Risico | Impact | Prior. |
|---|:---:|:---:|:---:|
| Bij wijzigingen in het OCSF-schema of nieuwe event classes kan de bestaande normalisatielaag in shared/normalization inkomende events onvolledig of fout mappen, wat leidt tot verkeerde intent-routing. | 4 | 3 | 2 |

| Actie | Actietype |
|---|---|
| Schema-versiebeheer invoeren, compatibility tests op normalisatie uitvoeren en onbekende velden gecontroleerd verwerken in plaats van stil te droppen. | Inperken |

### R10 - Ingress-contracten droppen geldige events (Testrelevantie: H)
| Omschrijving | Risico | Impact | Prior. |
|---|:---:|:---:|:---:|
| Strikte Pydantic-contracten in shared/ingress/contracts.py kunnen events met kleine schema-afwijkingen volledig weigeren zonder duidelijke dead-letter of audit trail. | 3 | 4 | 2 |

| Actie | Actietype |
|---|---|
| Validatieregels verfijnen met tolerante parsing waar verantwoord, dead-letter afhandeling inbouwen en afwijzingen verplicht auditen. | Inperken |

### R11 - Lambda payload- en timeout-limieten veroorzaken dataverlies (Testrelevantie: M)
| Omschrijving | Risico | Impact | Prior. |
|---|:---:|:---:|:---:|
| Grote of gebatchte provider-payloads kunnen API Gateway/Lambda-limieten overschrijden of timeouts veroorzaken, waardoor batches alerts of IAM-events de Temporal-workflows niet bereiken. | 3 | 3 | 2 |

| Actie | Actietype |
|---|---|
| Payloadgrenzen afdwingen, batching opsplitsen, timeouts monitoren en replaybare retry-mechanismen voorzien op ingressniveau. | Inperken |

### R12 - DynamoDB-TTL fout geconfigureerd (Testrelevantie: M)
| Omschrijving | Risico | Impact | Prior. |
|---|:---:|:---:|:---:|
| Verkeerde TTL-attribuutnaam of ontbreken van TTL op tabellen voor HiTL-tokens of subscriptions kan tokens onbeperkt geldig houden of te vroeg verwijderen, met security- of beschikbaarheidsimpact. | 3 | 3 | 2 |

| Actie | Actietype |
|---|---|
| TTL-configuraties automatisch valideren in infrastructuurchecks, levensduurtests uitvoeren en alarmen instellen op afwijkend tokenverloop. | Inperken |

### R13 - DynamoDB-throttling bij piekbelasting (Testrelevantie: M)
| Omschrijving | Risico | Impact | Prior. |
|---|:---:|:---:|:---:|
| Onvoldoende provisioned capacity of onrealistische autoscaling-profielen voor tabellen kunnen tijdens incidentspikes tot throttling en gefaalde writes of reads leiden. | 4 | 3 | 2 |

| Actie | Actietype |
|---|---|
| Capacityprofielen afstemmen op piekbelasting, throttling-alerts instellen en fallback/retry op storage-operaties afdwingen. | Inperken |

### R14 - Terraform resource drift en env-mismatch (Testrelevantie: M)
| Omschrijving | Risico | Impact | Prior. |
|---|:---:|:---:|:---:|
| Verschillen tussen Terraform-states of omgevingen zorgen ervoor dat bepaalde workflows alleen in sommige omgevingen falen. | 3 | 3 | 2 |

| Actie | Actietype |
|---|---|
| Drift-detectie en environment parity checks automatiseren, met verplichte plan-review vóór uitrol naar elke omgeving. | Inperken |

### R15 - Temporal worker- en task-queue-misconfiguratie (Testrelevantie: H)
| Omschrijving | Risico | Impact | Prior. |
|---|:---:|:---:|:---:|
| Fout geconfigureerde workers of ontbrekende registratie van task queues kunnen maken dat bepaalde workflows nooit gepolled of extreem traag uitgevoerd worden. | 3 | 4 | 2 |

| Actie | Actietype |
|---|---|
| Queue-registratie valideren bij startup, health checks op polling toevoegen en performantiegrenzen monitoren per queue. | Inperken |

### R16 - Onjuiste Graph-token lifecycle in activities (Testrelevantie: M)
| Omschrijving | Risico | Impact | Prior. |
|---|:---:|:---:|:---:|
| Activities en shared/graph_client.py kunnen access tokens te lang cachen of verkeerd vernieuwen, wat resulteert in golven van 401-fouten en gefaalde IAM- of alertacties. | 4 | 3 | 2 |

| Actie | Actietype |
|---|---|
| Token lifecycle expliciet testen, cache-invalidation op vervaldatum afdwingen en refresh-failures gecontroleerd opvangen met retrybeleid. | Inperken |

### R17 - Onvoldoende logging en correlatie over lagen heen (Testrelevantie: M)
| Omschrijving | Risico | Impact | Prior. |
|---|:---:|:---:|:---:|
| Als workflows, activities en ingress beperkt gestructureerd loggen, is root cause analysis en forensische reconstructie van incidenten zeer moeilijk. | 4 | 2 | 2 |

| Actie | Actietype |
|---|---|
| Gestandaardiseerde logvelden (tenant, workflow-id, provider, intent) verplichten en correlatie-id end-to-end doorgeven over alle lagen. | Inperken |

### R18 - Lage testdekking op kritieke modules (Testrelevantie: H)
| Omschrijving | Risico | Impact | Prior. |
|---|:---:|:---:|:---:|
| Beperkte unit- en integratietesten voor shared/ingress, shared/normalization, connectors en kern-workflows vergroten de kans dat refactors of nieuwe providers regressies veroorzaken in multi-tenant SOC-flows. | 4 | 4 | 3 |

| Actie | Actietype |
|---|---|
| Risicogedreven testdekking verhogen op kritieke modules, minimale coverage gates instellen en regressiesets uitbreiden per integratiepad. | Inperken |



# Teststrategie
Testen is in dit project een doorlopende activiteit per iteratie, niet enkel een slotfase. Nieuwe wijzigingen worden eerst lokaal gevalideerd en daarna opgenomen in de regressieset (`python -m pytest -q`). Voor elk gate-moment wordt de volledige suite opnieuw gedraaid, met prioriteit voor de hoogste risico's uit de risicoanalyse. Warre voert de technische tests uit; Xander reviewt de resultaten; Maxim en Dustin valideren gerichte operationele scenario's (SOC/HiTL). De visie is risicogedreven: eerst kritieke paden afdekken, daarna verbreden.

| Testtype | Gepland? | Bereik en criteria |
|----------|----------|--------------------|
| Unit testen | Ja | Bereik: datamodellen, validatieregels, helperlogica en individuele activity/connectorfuncties. Geslaagd als 100% van de unitset slaagt, geen onverwachte exceptions optreden en de line coverage op kritieke backendmodules minimaal 70% bedraagt. |
| Integratie testen | Ja | Bereik: samenwerking tussen ingress, routing, normalisatie, activities en connector-dispatch met gemockte externe afhankelijkheden. Geslaagd als intent- en tenant-routing correct zijn, foutvertaling consistent gebeurt en er geen dubbele side effects optreden bij retries. Verwachting: integratietests dekken alle drie kernprocessen minstens 1 positief en 1 negatief scenario. |
| Systeem testen | Beperkt | Bereik: ketenscenario's in gesimuleerde stack, zonder volledige live productie-infra. Geslaagd als de volledige verwerkingsketen per kernproces end-to-end doorloopt zonder blokkerende fouten. Verwachting: minimaal 1 representatief ketenscenario per kernproces. |
| Sanity testen | Ja | Bereik: snelle rooktest op de meest kritieke paden na refactor of vóór gate. Geslaagd als de sanity-set 100% slaagt; bij 1 failure wordt vrijgave geblokkeerd. Verwachting: sanity-set dekt alle high-priority risicozones minstens op basisniveau. |
| Interface testen | Ja | Bereik: API-contracten, headers, payloadstructuren, signatures en callbackparameters. Geslaagd als geldige input tot correcte verwerking leidt (2xx of verwacht pad) en ongeldige input deterministisch met de juiste validatiefout wordt geweigerd. Verwachting: 100% dekking van verplichte contractvelden en auth-controles. |
| Regressie testen | Ja | Bereik: volledige geautomatiseerde testsuite per iteratie, vóór gate en bij bugfixes. Geslaagd als alle bestaande tests groen blijven en elke opgeloste bug minimaal 1 nieuwe regressietest toevoegt. Verwachting: regressieset bewaakt alle eerder opgeleverde kernfunctionaliteit. |
| Beta- of acceptatietesten | Nee (formeel) | Bereik: geen formeel extern beta-traject in deze PoC-fase. Slaagcriterium voor interne acceptatie blijft: overeengekomen kernscenario's zijn blocker-vrij gevalideerd door projectstakeholders. Coverageverwachting voor formele beta: 0% in huidige fase. |
| Performantie testen (load, spike, stress) | Nee (voor nu) | Bereik: geen geautomatiseerde load/spike/stresscampagne in huidige scope. Slaagcriterium in deze fase: functionele tests blijven stabiel onder normale PoC-belasting. Coverageverwachting voor formele performantiecampagne: 0% in huidige fase; gepland voor vervolgfase. |
| Security testen | Gedeeltelijk | Bereik: negatieve paden rond authenticatie, autorisatie, tenant-context, tokenverloop en veilige foutafhandeling. Geslaagd als ongeldige of ongeautoriseerde aanvragen steeds veilig falen zonder datalek. Verwachting: 100% dekking van kritieke negatieve auth- en isolatiescenario's; DAST/SAST/pentest nog niet in scope. |
| Cross-browser en cross-systeem testen | Nee | De applicatie is een backend-orchestrator zonder webfrontend; clients zijn providers (Graph, EDR, ticketing) en operators via API's. Browser- of OS-specifieke rendering speelt geen rol, dus cross-browser/-systeemtests zijn niet zinvol en worden bewust niet gepland. |
| Usability testen | Nee (formeel) | Er is geen eindgebruikers-UI; usability is hier vooral relevant voor operators via toekomstige portals of dashboards, die buiten de scope van deze PoC vallen. Voor de huidige CLI/API-only setup volstaan duidelijke logs en foutboodschappen; formele usabilitytests worden daarom niet ingepland. |

# Testomgeving
| Naam | Versie | Verdeler | Omschrijving | Ref |
|---|---|---|---|---|
| Python runtime | 3.11 | Python Software Foundation | Runtime waarin de testcommando's en testcode uitgevoerd worden. | [2] |
| pytest | >=8.0 | pytest-dev | Kernframework voor unit-, integratie-, regressie- en sanity-tests. | [3] |
| pytest-asyncio | >=0.24.0 | pytest-dev | Ondersteuning voor asynchrone testscenario's. | [4] |
| pytest-mock | >=3.14.0 | pytest-dev | Mocking van externe afhankelijkheden tijdens tests. | [5] |
| temporalio.testing | >=1.9.0 | Temporal Technologies | Ingebouwde testtooling in de Temporal Python SDK voor unit-, integratie- en end-to-end tests met time-skipping voor langlopende workflowlogica. | [7] |
| Temporal Server | 1.29.1 | Temporal Technologies | Lokale Temporal runtime om workflowgedrag in testscenario's te valideren. | [6] |
| Temporal UI | 2.34.0 | Temporal Technologies | Manuele inspectie van workflowruns, status en foutanalyse tijdens validatie. | [8] |
| Temporal Admin Tools | 1.29.1-tctl-1.18.4-cli-1.5.0 | Temporal Technologies | Ondersteunt namespace-setup en beheer in de lokale teststack. | [9] |
| PostgreSQL | 16 | PostgreSQL Global Development Group | Persistence van Temporal-testdata in lokale compose-omgeving. | [10] |

Hardware en services: er zijn geen aparte fysieke testservers gebruikt; de testuitvoering gebeurt op de ontwikkelomgeving met lokale containerized services voor Temporal en databasecomponenten.

Resultaatcaptatie en verwerking: testresultaten worden centraal gecapteerd via pytest-uitvoer en exitcodes per iteratie en gate-moment. Fouten worden geclassificeerd per testtype en teruggekoppeld naar risico-prioriteiten (hoog, middel, laag) voor remediatie in de volgende iteratie. In latere tekst worden geen bijkomende testtools geïntroduceerd buiten deze centrale lijst.

# Bronvermelding
[1] Gehre, W. (2026). Blueprint Process Orchestrator. Ongepubliceerd intern stagedocument, Secamo.

[2] Python Software Foundation. (2022-10-24). Python 3.11.0 documentation. Opgehaald van https://www.python.org/downloads/release/python-3110/.

[3] pytest-dev. (z.d.). pytest documentation. Opgehaald op 2026-03-27 van https://docs.pytest.org/.

[4] pytest-dev. (z.d.). pytest-asyncio documentation. Opgehaald op 2026-03-27 van https://pytest-asyncio.readthedocs.io/.

[5] pytest-dev. (z.d.). pytest-mock documentation. Opgehaald op 2026-03-27 van https://pytest-mock.readthedocs.io/.

[6] Temporal Technologies. (z.d.). Temporal documentation. Opgehaald op 2026-03-27 van https://docs.temporal.io/.

[7] Temporal Technologies. (z.d.). Python SDK testing suite. Opgehaald op 2026-03-27 van https://docs.temporal.io/develop/python/testing-suite.

[8] Temporal Technologies. (z.d.). Temporal Web UI. Opgehaald op 2026-03-27 van https://docs.temporal.io/web-ui.

[9] Temporal Technologies. (z.d.). temporalio/admin-tools (Docker Hub). Opgehaald op 2026-03-27 van https://hub.docker.com/r/temporalio/admin-tools.

[10] PostgreSQL Global Development Group. (z.d.). PostgreSQL 16 documentation. Opgehaald op 2026-03-27 van https://www.postgresql.org/docs/16/.
