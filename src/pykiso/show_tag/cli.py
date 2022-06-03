##########################################################################
# Copyright (c) 2010-2022 Robert Bosch GmbH
# This program and the accompanying materials are made available under the
# terms of the Eclipse Public License 2.0 which is available at
# http://www.eclipse.org/legal/epl-2.0.
#
# SPDX-License-Identifier: EPL-2.0
##########################################################################

"""
Integration Test Framework
**************************

:module: cli

:synopsis: Show the tag informations to the given tests

.. currentmodule:: cli


"""
import collections
import json as json_lib
import logging
import pprint
import sys
import time
from pathlib import Path
from typing import NamedTuple, Optional, Tuple
import unittest

import click
import sys

import pandas as pd
from tabulate import tabulate

from pykiso import __version__
from pykiso.config_parser import parse_config
from pykiso.global_config import Grabber
from pykiso.test_coordinator.test_suite import flatten, tc_sort_key
from pykiso.types import PathType

import unittest.mock as mock

# use to store the selected logging options
LogOptions = collections.namedtuple("LogOptions", "log_path log_level report_type")
log_options: Optional[NamedTuple] = None
logger = None


def initialize_logging(log_path: PathType, log_level: str) -> logging.Logger:
    """Initialize the logging.

    Sets the general log level, output file or STDOUT and the
    logging format.

    :param log_path: path to the logfile
    :param log_level: any of DEBUG, INFO, WARNING, ERROR

    :returns: configured Logger
    """
    root_logger = logging.getLogger()
    log_format = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(module)s:%(lineno)d: %(message)s"
    )
    levels = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
    }

    # update logging options
    global log_options
    log_options = LogOptions(log_path, log_level, "text")

    # if log_path is given create use a logging file handler
    if log_path is not None:
        log_path = Path(log_path)
        if log_path.is_dir():
            fname = time.strftime("%Y-%m-%d_%H-%M-test.log")
            log_path = log_path / fname
        file_handler = logging.FileHandler(log_path, "a+")
        file_handler.setFormatter(log_format)
        file_handler.setLevel(levels[log_level])
        root_logger.addHandler(file_handler)
    # if log_path is not given and report type is not junit just
    # instanciate a logging StreamHandler
    if log_path is None:
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(log_format)
        stream_handler.setLevel(levels[log_level])
        root_logger.addHandler(stream_handler)

    root_logger.setLevel(levels[log_level])

    return logging.getLogger(__name__)


def get_logging_options() -> LogOptions:
    """Simply return the previous logging options.

    :return: logging options log path, log level and report type
    """
    return log_options


def get_yaml_files(config: PathType) -> tuple:
    """Return the list of yaml files included in the config

    :param config: yaml file or folder
    :return: tuple of yaml Path
    """
    if Path(config).is_dir():
        # search for all yaml files contained in it
        config_files = tuple(
            file.resolve()  # Get full path of the file
            # recursive search in the config folder
            for file in Path(config).rglob("*")
            if file.name.__contains__(".yaml")
        )
        if not config_files:
            raise FileNotFoundError("Yaml files not found")
    else:
        config_files = tuple(
            [Path(config).resolve() if config.__contains__(".yaml") else ()]
        )
        if not all(config_files):
            raise FileNotFoundError("This is not a yaml file")

    return config_files


def get_test_list(cfg_dict: dict) -> dict:
    """Return the list of tests impacted by the yaml

    :param cfg_dict: configuration dict of the yaml file
    :return: list of tests impacted by the yaml file
    """
    test_case_list = []

    # if the yaml file has a test suite list
    if "test_suite_list" in cfg_dict:

        for test_suite_configuration in cfg_dict["test_suite_list"]:

            current_tc_list = []
            logger.debug(
                "test suite configuration:\n{}".format(
                    pprint.pformat(test_suite_configuration)
                )
            )

            # load tests from the specified folder
            loader = unittest.TestLoader()
            found_modules = loader.discover(
                test_suite_configuration["suite_dir"],
                pattern=test_suite_configuration["test_filter_pattern"],
                top_level_dir=test_suite_configuration["suite_dir"],
            )

            # sort the test case list by ascendant using test suite and test case id
            current_tc_list = sorted(flatten(found_modules), key=tc_sort_key)

            # get the test suite id if there is one
            test_suite_id = (
                test_suite_configuration["test_suite_id"]
                if "test_suite_id" in test_suite_configuration
                else None
            )

            # remove all tests who dont match the suite id
            if test_suite_id:
                current_tc_list = [
                    test
                    for test in current_tc_list
                    if not test.test_suite_id or test_suite_id == test.test_suite_id
                ]
            test_case_list += current_tc_list

    return test_case_list


def get_tag_list(test_case_list: dict) -> dict:
    """Return the list of tag and values contained in the test case list

    :param test_case_list: list of test case
    :return: dict of tags name with their values
    """
    tag_dict = {}
    # search the tag for each tests
    for test_suite in test_case_list:

        if test_suite.tag:
            for tag_name, values in test_suite.tag.items():
                # create a tuple if the tag doesnt exist yet
                if tag_name not in tag_dict:
                    tag_dict[tag_name] = ()
                if isinstance(values, str):
                    tag_dict[tag_name] += tuple([values])
                else:
                    tag_dict[tag_name] += tuple(value for value in values)

                # remove duplicated tag values
                tag_dict[tag_name] = tuple(sorted(set(tag_dict[tag_name])))

    return tag_dict


def format_result_to_dataframe(result: dict) -> pd.DataFrame:
    """Format the result to a fancy DataFrame"""
    result_cleaned = dict(result)
    for file_name, tags in result.items():
        for tag_name, tag in tags.items():
            result_cleaned[file_name][tag_name] = ", ".join(tag)

    df = pd.DataFrame(result).fillna("")
    return df


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "-c",
    "--test-configuration",
    required=True,
    type=click.Path(exists=True, dir_okay=True, readable=True),
    multiple=True,
    help="path to the test configuration file or folder (in YAML format)",
)
@click.option(
    "-l",
    "--log-path",
    required=False,
    default=None,
    type=click.Path(writable=True),
    help="path to log-file or folder. If not set will log to STDOUT",
)
@click.option(
    "--log-level",
    required=False,
    default="INFO",
    type=click.Choice(
        "DEBUG INFO WARNING ERROR".split(" "),
        case_sensitive=False,
    ),
    help="set the verbosity of the logging",
)
@click.option(
    "--json/--no-json",
    default=False,
    help="default, test results are only displayed in the console",
)
@click.version_option(__version__)
@Grabber.grab_cli_config
def main(
    test_configuration: Tuple[PathType],
    log_path: PathType = None,
    log_level: str = "INFO",
    json: bool = False,
):
    """Embedded Integration Test Framework - CLI Entry Point.

    \f
    :param test_configuration_file: path to the YAML config file
    :param log_path: path to directory or file to write logs to
    :param log_level: any of DEBUG, INFO, WARNING, ERROR
    :param report_type: if "test", the standard report, if "junit", a junit report is generated
    """

    if log_path and Path(log_path).is_file():
        Path(log_path).unlink()

    # Set the logging
    global logger
    logger = initialize_logging(log_path, log_level)

    # mock the auxiliaries
    sys.modules["pykiso.auxiliaries"] = mock.MagicMock()

    # init variables
    result = {}

    logger.info("Start show tag CLI")
    # for each configuration given by the user
    for config in test_configuration:

        # get all yaml files
        yaml_files = get_yaml_files(config)

        for config_file in yaml_files:
            logger.debug("config file: {}".format(pprint.pformat(config_file.name)))

            # init for each yaml file
            result[config_file.name] = {}

            # Get YAML configuration
            cfg_dict = parse_config(config_file)

            # Get the list of tests impacted by the config file
            test_case_list = get_test_list(cfg_dict)

            # number of tests impacted by the yaml file
            # note : this will also count tearDown and setUp
            result[config_file.name]["Nbr of tests"] = len(test_case_list)
            result[config_file.name] = get_tag_list(test_case_list)

    logger.info("All configurations has been processed successfully")

    logger.info("Output Result")

    # JSON
    if json:
        with open("data.json", "w", encoding="utf-8") as f:
            json_lib.dump(result, f, ensure_ascii=False, indent=4)
            logger.info("data.json file is created")
    else:
        logger.info(
            "Be carefull if there is already a json file created, it's from a previous run !"
        )

    # TABULATE
    df = format_result_to_dataframe(result)
    logger.info("\n{}\n".format(tabulate(df.T, headers="keys", tablefmt="grid")))
