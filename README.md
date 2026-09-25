# Terraform Analysis & Cloud Security Platform

Modular Python platform for parsing Terraform HCL code, extracting resources and dependency relationships, normalizing infrastructure entities, performing security rules scanning, and analyzing attack surfaces and risk.

## Modular Architecture (`app/`)

```
project_root/
│
├── app/
│   ├── parser/            # HCL loading & AST extraction
│   │   ├── hcl_parser.py
│   │   └── ast_extractor.py
│   │
│   ├── core/              # Schema normalization, relationships & validation
│   │   ├── converter.py
│   │   ├── relationships.py
│   │   ├── type_mapper.py
│   │   └── schema_validator.py
│   │
│   ├── security/          # Security rule definitions, analyzer & scanner
│   │   ├── analyzer.py
│   │   ├── rules.py
│   │   ├── scanner.py
│   │   ├── severity.py
│   │   └── llm_service.py
│   │
│   ├── models/            # Domain models (Resource, Relationship, Finding)
│   │   ├── resource.py
│   │   ├── relationship.py
│   │   └── finding.py
│   │
│   ├── graph/             # Graph node/edge representations & builders
│   │   ├── nodes.py
│   │   ├── edges.py
│   │   └── builder.py
│   │
│   ├── attack/            # Attack paths, choke points & crown jewels
│   │   ├── entry_points.py
│   │   ├── attack_paths.py
│   │   ├── choke_points.py
│   │   └── crown_jewels.py
│   │
│   ├── risk/              # Risk scoring & blast radius calculations
│   │   ├── scorer.py
│   │   └── blast_radius.py
│   │
│   └── output/            # JSON output formatting & persisting
│       └── json_writer.py
│
├── input/                 # Sample Terraform code test scenarios
├── output/                # Generated JSON artifacts
├── tests/                 # Unit test suite
├── main.py                # Pipeline CLI entry point
└── requirements.txt       # Project dependencies
```

## Running the Pipeline

To run the main analysis pipeline against a folder of Terraform `.tf` files:

```bash
python main.py -i input/validation_tes -o output/terraform.json
```

## Running Tests

To run the Pytest test suite:

```bash
python -m pytest
```
