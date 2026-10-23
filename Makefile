.PHONY: help install test test-unit test-sec test-ai lint run

help:
	@echo "Plateforme de Securisation des Bases TCIM"
	@echo "make install    : Installer les dependances"
	@echo "make test       : Executer l'ensemble des tests"
	@echo "make test-unit  : Executer les tests unitaires"
	@echo "make test-sec   : Executer les tests de securite BDD"
	@echo "make test-ai    : Executer les tests de classification IA"
	@echo "make run        : Demarrer l'API"

install:
	pip install -r requirements/test.txt

test:
	pytest --cov=src --cov-report=term-missing

test-unit:
	pytest tests/unit -v

test-sec:
	pytest tests/security -v

test-ai:
	pytest tests/ai -v

lint:
	ruff check src tests

run:
	uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload
