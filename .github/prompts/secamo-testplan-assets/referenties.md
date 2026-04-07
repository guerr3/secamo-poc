---
template_version: 1.4
algemeen_doel: Overtuig lezer dat oplossing robuust is en voldoet aan criteria. Beantwoord: "Wat zijn criteria voor 'goed genoeg'?" (testplan) en "Hoe goed presteert het?" (reflectieverslag, apart).
verwijder_in_finale: Alle cursieve sjabloontekst en deze YAML.
---

# LLM‑Referentie: Testplan Sjabloon AP Hogeschool

Gebruik deze als context voor generatie: "Vul [sectie] in voor [jouw projectbeschrijving], volg instructies."

## Sectie‑overzichten

| Sectie | Verwacht karakters | Kerninstructies |
|--------|--------------------|-----------------|
| **Inleiding** | 750–1500 | - Specifiek voor *dit project* (geen algemeen testen-pleidooi).<br>- Doelgroep vermelden.<br>- Einde: samenvatting (2–4 zinnen) + conclusie (1 zin).<br>- Verwijs naar Blueprint. |
| **Projectbeschrijving en scope** | 750–1500 | - Samenvatting uit Blueprint.<br>- Functionaliteiten kort opsommen.<br>- Geen testen vermelden. |
| **Belanghebbenden** | N.v.t. | - Alle betrokkenen (ontwikkelaars, testers, incl. jezelf + minstens 1 andere tester).<br>- Bijdrage: analyse, sponsor, tester, nalezen, PM.<br>- Externe: expliciete goedkeuring. |
| **Risicoanalyse** | 1500–5000 | - 10–20 app‑specifieke risico's (geen meta zoals ziekte/tijd).<br>- Technieken: Ishikawa, Delphi, interviews, lessons learnt.<br>- Afhandeling: Aanvaarden/Vermijden/Transfereren/Inperken/Exploiteren.<br>- Risico (0–5): kans.<br>- Impact (0–5): ernst.<br>- Prioriteit: rnd(1/5 × risico × impact), sorteer dalend.<br>- Prioriteer testactiviteiten. |
| **Teststrategie** | 1000–3000 | - Integratie in project (sprints, fase, verantwoordelijkheden, visie).<br>- Overzicht *alle* courant testtypes (unit, integratie, systeem, sanity, interface, regressie, acceptatie, performantie, security, cross-browser/systeem, usability).<br>- Per type: Gepland? + waarom wel/niet + criteria/dekking (meetbaar, niet dubbelzinnig). |
| **Testomgeving** | N.v.t. | - Software: naam, versie, verdeler, ref.<br>- Hardware/services: specs.<br>- Hoe resultaten gecapteerd/omgezet.<br>- Centraal: geen nieuwe tools later. |
| **Overig** | - | - Versiebeheer: 0.x (draft), 1.00+ (finale), incl. verspreiding/wijzigingen.<br>- Termen: alfabetisch, eerste gebruik = voluit + afkorting.<br>- Bronvermelding: APA‑stijl. |

## Risico‑schalen (voor tabellen)

**Risico (kans):**
- 0: Nooit
- 1: Heel klein
- 2: Matig
- 3: Groot
- 4: Erg groot
- 5: Quasi zeker 1x

**Impact:**
- 0: Geen
- 1: Minimaal/kort of onderhoudbaarheid
- 2: Enkele functionaliteiten tijdelijk down
- 3: Belangrijk deel down
- 4: Meeste down, maar overbrugbaar
- 5: Alles down

## Prompt‑sjablonen voor LLM

- **Genereer sectie**: "Genereer [Inleiding] voor testplan [project]: [korte beschrijving]. Volg instructies: [plak YAML van sectie]. Output alleen de tekst."
- **Risico's**: "Genereer 15 risico's voor [app]: gebruik schalen, prioriteer, stel afhandeling voor."
- **Teststrategie**: "Overzicht testtypes voor [project]: alle courant types, gepland/neen + waarom + criteria."