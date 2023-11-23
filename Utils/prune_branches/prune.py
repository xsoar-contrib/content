#!/usr/bin/env python3
"""
Prunes GitHub repository branches according to a specific pattern
"""

__author__ = "Kobbi Gal"
__version__ = "0.1.0"
__license__ = "MIT"

import argparse
import sys
from datetime import datetime
from dateutil.relativedelta import relativedelta
from typing import Any
from uuid import uuid4
from pathlib import Path
import os

UUID = str(uuid4())

import logging
log_filename = os.path.basename(f"prune-{UUID}.log")
log_file_path = os.path.join("/tmp", log_filename)
Path(log_file_path).touch()
logging.basicConfig(
    filename=log_file_path,
    format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
    datefmt='%H:%M:%S',
    level=logging.INFO
)

logger = logging.getLogger(__file__)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from git import InvalidGitRepositoryError, NoSuchPathError, Repo
from github import Github
from github.GithubException import GithubException
# from github.GithubException import UnknownObjectException
import pandas as pd

def main(args):

    """
    Prune GitHub branches of a provided cloned local repository based on the specified branch name filter and months ago.
    
    The procedure is:

    1. Open the cloned `git` repository locally. Make sure you run `git fetch|pull` to retrieve all remote refs.
    2. Retrieve a list of the remote references.
    3. Iterate over each reference to retrieve the branch from GitHub.
    4. Attempt to get and remove the protection on that branch.
    5. Attempt to remove the remote branch. If a Pull Request was opened through the remote branch, it will be closed.

    The script outputs two files:
    - `/tmp/prune-UUID.log`: To change verbosity, set the `logging.basicConfig(level=logging.DEBUG)`
    - `/tmp/prune-REPO_NAME-UUID.csv`: A CSV that summarizes the execution results. Includes branch name, last modified date, whether it was deleted or not.
    
    Args:
        - `local_git_path` (``str``): Path to the local `git` repository.
        - `gh_token` (``str``): The GitHub token used to authenticate with GitHub.
        - `gh_repo` (``str``): The repo name in ORG/REPO format.
        - `filter` (``str``): A filter used to match which branches should be processed. 
        e.g given 'contrib', only branches with 'contrib' in their name will be processed.
        - `remote_name` (``str``): The name of the remote if different than 'origin'.
        - `months_ago` (``int``): The number of months used as cutoff. Branches that were modified after this cutoff will be skipped.
        - `limit` (``int``): The number of branches to delete.
        - `is_dry_run` (``bool``): If set, it will simulate deletion of the remote branch on GitHub.
    """

    # Create git repo
    try:
        local_repo = Repo(args.local_git_path)
    except (InvalidGitRepositoryError, NoSuchPathError):
        logger.error("Git repository not found in path. Terminating...")
        sys.exit(1)

    # Retrieve all remote refs
    remote_name = args.input_remote_name
    logger.debug(f"Retrieving all remote refs from '{remote_name}'...")
    try:
        remote_refs = local_repo.remote(name=remote_name).refs
    except ValueError as ve:
        logger.error(f"Unable to retrieve refs from remote '{remote_name}': {str(ve)}. Terminating...")
        sys.exit(1)

    # Iterate over all remote refs and check if the input is a substring of the ref name
    remote_branches = []
    for r in remote_refs:
        remote_branch_name = r.name.replace("origin/", "")
        if args.branch_name_filter in remote_branch_name:
            remote_branches.append(remote_branch_name)

    logger.info(f"Found {len(remote_branches)} remote branches in repository '{args.local_git_path}' based on branch name filter '{args.branch_name_filter}':")
    logger.debug('\n'.join(remote_branches))

    # Authenticate with GitHub
    gh = Github(args.gh_token, verify=False)
    gh_repo = gh.get_repo(args.gh_repo)

    months_ago = args.months_ago
    logger.debug(f"Creating cutoff date based on {months_ago} months ago")
    cutoff_date = datetime.today() + relativedelta(months=(-1 * months_ago))
    logger.info(f"Cutoff date: {cutoff_date.strftime('%Y/%m/%d %H:%M:%S')}")
    summary: list[dict[str, Any]] = []

    # Iterate over branches 
    logger.info(f"Limiting deletion of the first {args.limit} branches")

    # If the number of remote branches is larger than the limit
    # we want to take that subset
    if len(remote_branches) > args.limit:
        logger.info(f"The limit supplied ({args.limit}) is smaller than the remote branches, iterating over subset of remote branches...")
        remote_branches = remote_branches[:args.limit]

    for b in remote_branches:
        entry: dict[str, Any] = {"branch": b}
        try:
            rb = gh_repo.get_branch(b)

            # Parse the last commit modified date
            # When there's only 1 commit, the last_modified attribute is None
            # So we use the 1st commit date instead
            branch_last_modified = rb.commit.last_modified
            if not branch_last_modified:
                branch_last_modified_dt = rb.commit.commit.author.date.replace(tzinfo=None)
            else:
                branch_last_modified_dt = datetime.strptime(branch_last_modified, "%a, %d %b %Y %H:%M:%S %Z")

            entry['branch_last_modified'] = branch_last_modified_dt.strftime("%Y/%m/%d %H:%M:%S")
            # If the branch was created after the cutoff date, we want to skip deletion
            if branch_last_modified_dt > cutoff_date:
                entry['deleted'] = False
                entry['comment'] = f"Not deleted because it's after the cutoff date {cutoff_date.strftime('%Y/%m/%d %H:%M:%S')}"
                continue

            try:
                # A GithubException will be thrown in case a branch is not protected
                # Or when we attempt to delete an unprotected branch
                rb.get_protection()
                rb.remove_protection()
                logger.debug(f"Protection for branch '{rb.name}' removed successfully")
            except GithubException as ghe:
                logger.warning(f"Unable to get or remove protection from remote branch '{b}': {str(ghe)}")
            
            # If in case the get/rm protection fails (e.g. protection wasn't found and cannot be removed)
            # we still want to delete the branch (if we're not in dry run).
            finally:
                if not args.is_dry_run:
                    try:
                        logger.debug(f"Attempting to delete branch '{b}'...")
                        ref = gh_repo.get_git_ref(f"heads/{b}")
                        ref.delete()
                        entry["deleted"] = True
                        logger.debug(f"Branch '{b}' deleted successfully")
                    except GithubException as ghe:
                        msg = f"Failed deleting the branch '{b}': {str(ghe)}"
                        logger.error(msg)
                        entry["deleted"] = False
                        entry["comment"] = msg
                else:
                    entry["deleted"] = False
                    entry["comment"] = "Was supposed to be deleted but dry run was set."

        except GithubException as ghe:
            logger.error(f"Unable to find remote branch '{b}' from GitHub: {str(ghe)}")
            entry["branch_last_modified"] = "N/A"
            entry["deleted"] = False
            entry["comment"] = "Branch not found in GitHub remotes"
            continue
        finally:
            summary.append(entry)

    df = pd.DataFrame(summary)
    output_file = f"/tmp/prune-{args.gh_repo.split('/')[1]}-{UUID}.csv"
    logger.info(f"Saving summary to '{output_file}'...")
    df.to_csv(output_file)

    logger.info(f"Log file can be found in '{log_file_path}'")

if __name__ == "__main__":
    """ This is executed when run from the command line """
    parser = argparse.ArgumentParser()

    parser.add_argument("local_git_path", help="Path to a local git repository")
    parser.add_argument("gh_token", help="GitHub token")
    parser.add_argument("gh_repo", help="The GitHub repository to prune branches from in '$ORG_NAME/$REPO_NAME' format, e.g. kgal-pan/content-fork")
    parser.add_argument(
        "-f", "--filter",
        action="store",
        dest="branch_name_filter",
        help="Branch name filter.\nOnly branches that are a substring of the provided filter will be processed"
    )
    parser.add_argument(
        "-r", "--remote-name",
        action="store",
        dest="input_remote_name",
        default="origin",
        help="The remote name. Defaults to 'origin'"
    )
    parser.add_argument(
        "-m", "--months-ago",
        action="store",
        dest="months_ago",
        default=3,
        type=int,
        help="The number of months to use as cutoff. Defaults to 3"
    )
    parser.add_argument(
        "-d", "--dry-run",
        action="store_true",
        dest="is_dry_run",
        help="True if you just want to print the branches to delete."
    )
    parser.add_argument(
        "-l", "--limit",
        action="store",
        dest="limit",
        default=100,
        type=int,
        help="The number of branches to delete",
    )


    args = parser.parse_args()
    main(args)