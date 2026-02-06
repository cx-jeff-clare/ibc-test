"""Unit tests for Django services."""

import pytest
from django.test import TestCase, RequestFactory
from django.contrib.auth.models import User
from unittest.mock import Mock, patch, MagicMock, call
from decimal import Decimal
from datetime import datetime

from web.services import (
    AccountService, CashAccountService, CreditAccountService,
    ActivityService, TransferService, StorageService
)
from web.models import Account, CashAccount, CreditAccount, Transaction, Transfer
from tests.base import BaseUnitTestCase


class TestAccountService(BaseUnitTestCase):
    """Unit tests for AccountService."""

    def setUp(self):
        """Set up test data."""
        super().setUp()
        self.account_service = AccountService()
        self.factory = RequestFactory()

        # Sample account data
        self.account_data = {
            'username': 'testuser',
            'name': 'Test',
            'surname': 'User',
            'password': 'testpass123'
        }

    @patch('web.services.User.objects.get')
    @patch('web.services.AccountService.find_users_by_username_and_password')
    def test_authenticate_existing_user_success(self, mock_find_users, mock_get_user):
        """Test successful authentication with existing user."""
        # Setup mocks
        mock_account = Mock()
        mock_find_users.return_value = [mock_account]  # Found account

        mock_user = Mock()
        mock_user.username = 'testuser'
        mock_get_user.return_value = mock_user

        # Create request with POST data
        request = self.factory.post('/login', {
            'username': 'testuser',
            'password': 'testpass123'
        })

        # Test authentication
        result = self.account_service.authenticate(request, 'testuser', 'testpass123')

        # Verify results
        self.assertEqual(result, mock_user)
        mock_find_users.assert_called_once_with('testuser', 'testpass123')
        mock_get_user.assert_called_once_with(username='testuser')

    @patch('web.services.AccountService.find_users_by_username_and_password')
    def test_authenticate_new_user_creation(self, mock_find_users):
        """Test authentication creates new Django user when not exists."""
        # Setup mocks
        mock_account = Mock()
        mock_find_users.return_value = [mock_account]  # Found account

        # Create request with POST data
        request = self.factory.post('/login', {
            'username': 'newuser',
            'password': 'newpass123'
        })

        # Mock User creation
        with patch('web.services.User') as mock_user_class:
            # Setup DoesNotExist on the mock class to match real exception
            from django.contrib.auth.models import User
            mock_user_class.DoesNotExist = User.DoesNotExist

            # Setup objects.get to raise DoesNotExist
            mock_user_class.objects.get.side_effect = User.DoesNotExist()

            mock_user_instance = Mock()
            mock_user_class.return_value = mock_user_instance

            result = self.account_service.authenticate(request, 'newuser', 'newpass123')

            # Verify new user was created
            mock_user_class.assert_called_once_with(username='newuser', password='newpass123')
            self.assertTrue(mock_user_instance.is_staff)
            self.assertFalse(mock_user_instance.is_superuser)
            mock_user_instance.save.assert_called_once()
            self.assertEqual(result, mock_user_instance)

    @patch('web.services.AccountService.find_users_by_username_and_password')
    def test_authenticate_john_gets_superuser(self, mock_find_users):
        """Test that username 'john' gets superuser privileges."""
        # Setup mocks
        mock_account = Mock()
        mock_find_users.return_value = [mock_account]

        request = self.factory.post('/login', {
            'username': 'john',
            'password': 'johnpass'
        })

        with patch('web.services.User') as mock_user_class:
            from django.contrib.auth.models import User
            mock_user_class.DoesNotExist = User.DoesNotExist
            mock_user_class.objects.get.side_effect = User.DoesNotExist()

            mock_user_instance = Mock()
            mock_user_class.return_value = mock_user_instance

            result = self.account_service.authenticate(request, 'john', 'johnpass')

            # Verify john gets superuser privileges
            self.assertTrue(mock_user_instance.is_superuser)
            self.assertTrue(mock_user_instance.is_staff)

    @patch('web.services.AccountService.find_users_by_username_and_password')
    def test_authenticate_no_account_found(self, mock_find_users):
        """Test authentication returns None when no account found."""
        # Setup mock to return empty list
        mock_find_users.return_value = []

        request = self.factory.post('/login', {
            'username': 'nonexistent',
            'password': 'wrongpass'
        })

        result = self.account_service.authenticate(request, 'nonexistent', 'wrongpass')

        self.assertIsNone(result)
        mock_find_users.assert_called_once_with('nonexistent', 'wrongpass')

    @patch('web.services.User.objects.get')
    def test_get_user_success(self, mock_get):
        """Test get_user returns user when found."""
        mock_user = Mock()
        mock_user.id = 1
        mock_get.return_value = mock_user

        result = self.account_service.get_user(1)

        self.assertEqual(result, mock_user)
        mock_get.assert_called_once_with(pk=1)

    @patch('web.services.User.objects.get')
    def test_get_user_not_found(self, mock_get):
        """Test get_user returns None when user not found."""
        from django.contrib.auth.models import User
        mock_get.side_effect = User.DoesNotExist()

        result = self.account_service.get_user(999)

        self.assertIsNone(result)
        mock_get.assert_called_once_with(pk=999)

    @patch('web.models.Account.objects.raw')
    def test_find_users_by_username_and_password(self, mock_raw):
        """Test find_users_by_username_and_password uses parameterized query."""
        mock_accounts = [Mock(), Mock()]
        mock_raw.return_value = mock_accounts

        result = AccountService.find_users_by_username_and_password('testuser', 'testpass')

        # Verify parameterized query is used (no string concatenation)
        expected_sql = "select * from web_account where username=%s AND password=%s"
        mock_raw.assert_called_once_with(expected_sql, ['testuser', 'testpass'])
        self.assertEqual(result, mock_accounts)

    @patch('web.models.Account.objects.raw')
    def test_find_users_by_username_and_password_sql_injection(self, mock_raw):
        """Test find_users_by_username_and_password uses parameterized query (injection prevented)."""
        mock_accounts = [Mock()]
        mock_raw.return_value = mock_accounts

        # Test with SQL injection payload - should be passed as param, not concatenated
        malicious_username = "admin'; DROP TABLE web_account; --"
        malicious_password = "anything"

        result = AccountService.find_users_by_username_and_password(malicious_username, malicious_password)

        # Parameterized query: SQL string has placeholders only; payload in params
        expected_sql = "select * from web_account where username=%s AND password=%s"
        mock_raw.assert_called_once_with(expected_sql, [malicious_username, malicious_password])

        # Verify injection payload is NOT in the SQL string (remediation)
        called_sql = mock_raw.call_args[0][0]
        self.assertNotIn("DROP TABLE", called_sql)
        self.assertNotIn("--", called_sql)

    @patch('web.models.Account.objects.raw')
    def test_find_users_by_username(self, mock_raw):
        """Test find_users_by_username SQL injection vulnerability."""
        mock_accounts = [Mock(), Mock()]
        mock_raw.return_value = mock_accounts

        result = AccountService.find_users_by_username('testuser')

        expected_sql = "select * from web_account where username='testuser'"
        mock_raw.assert_called_once_with(expected_sql)
        self.assertEqual(result, mock_accounts)

    @patch('web.models.Account.objects.raw')
    def test_find_users_by_username_sql_injection(self, mock_raw):
        """Test SQL injection vulnerability in find_users_by_username."""
        mock_accounts = [Mock()]
        mock_raw.return_value = mock_accounts

        # Test with SQL injection payload
        malicious_username = "'; SELECT * FROM web_account WHERE '1'='1"

        result = AccountService.find_users_by_username(malicious_username)

        # Verify the vulnerability is preserved
        called_sql = mock_raw.call_args[0][0]
        self.assertIn("SELECT * FROM web_account WHERE", called_sql)

    @patch('web.models.Account.objects.raw')
    def test_find_all_users(self, mock_raw):
        """Test find_all_users method."""
        mock_accounts = [Mock() for _ in range(5)]
        mock_raw.return_value = mock_accounts

        result = AccountService.find_all_users()

        expected_sql = "select * from web_account"
        mock_raw.assert_called_once_with(expected_sql)
        self.assertEqual(result, mock_accounts)
        self.assertEqual(len(result), 5)

    def test_account_service_inheritance(self):
        """Test that AccountService inherits from BaseBackend."""
        from django.contrib.auth.backends import BaseBackend
        self.assertIsInstance(self.account_service, BaseBackend)

    def test_authenticate_uses_request_post_data(self):
        """Test that authenticate method uses request.POST data."""
        # Create request with POST data
        request = self.factory.post('/login', {'username': 'post_user', 'password': 'post_pass'})

        with patch.object(self.account_service, 'find_users_by_username_and_password') as mock_find:
            mock_find.return_value = []

            # Even with parameters, it should use request.POST
            result = self.account_service.authenticate(request, 'param_user', 'param_pass')

            # Should call with POST values, not the parameters passed to authenticate
            mock_find.assert_called_once_with('post_user', 'post_pass')
            self.assertIsNone(result)


class TestCashAccountService(BaseUnitTestCase):
    """Unit tests for CashAccountService."""

    def setUp(self):
        """Set up test data."""
        super().setUp()

    @patch('web.models.CashAccount.objects.raw')
    def test_find_cash_accounts_by_username(self, mock_raw):
        """Test find_cash_accounts_by_username SQL injection vulnerability."""
        mock_accounts = [Mock(), Mock()]
        mock_raw.return_value = mock_accounts

        result = CashAccountService.find_cash_accounts_by_username('testuser')

        # Verify the vulnerable SQL query
        expected_sql = "select * from web_cashaccount  where username='testuser'"
        mock_raw.assert_called_once_with(expected_sql)
        self.assertEqual(result, mock_accounts)

    @patch('web.models.CashAccount.objects.raw')
    def test_find_cash_accounts_by_username_sql_injection(self, mock_raw):
        """Test SQL injection vulnerability in find_cash_accounts_by_username."""
        mock_accounts = [Mock()]
        mock_raw.return_value = mock_accounts

        # Test with SQL injection payload
        malicious_username = "'; UNION SELECT * FROM web_account; --"

        result = CashAccountService.find_cash_accounts_by_username(malicious_username)

        # Verify the vulnerability is preserved
        called_sql = mock_raw.call_args[0][0]
        self.assertIn("UNION SELECT", called_sql)
        self.assertIn("--", called_sql)

    @patch('web.services.connection')
    def test_get_from_account_actual_amount(self, mock_connection):
        """Test get_from_account_actual_amount with mocked database."""
        # Setup mock cursor
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = [1500.50]
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        result = CashAccountService.get_from_account_actual_amount('1234567890')

        # Verify database query
        mock_cursor.execute.assert_called_once_with(
            "SELECT availableBalance FROM web_cashaccount WHERE number = '1234567890'"
        )
        mock_cursor.fetchone.assert_called_once()
        self.assertEqual(result, 1500.50)

    @patch('web.services.connection')
    def test_get_from_account_actual_amount_not_found(self, mock_connection):
        """Test get_from_account_actual_amount when account not found."""
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = None
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        # This should raise an exception since it tries to access row[0]
        with self.assertRaises(TypeError):
            CashAccountService.get_from_account_actual_amount('nonexistent')

    @patch('web.services.connection')
    def test_get_id_from_number(self, mock_connection):
        """Test get_id_from_number with mocked database."""
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = [42]
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        result = CashAccountService.get_id_from_number('1234567890')

        # Verify database query
        mock_cursor.execute.assert_called_once_with(
            "SELECT id FROM web_cashaccount WHERE number = '1234567890'"
        )
        mock_cursor.fetchone.assert_called_once()
        self.assertEqual(result, 42)

    @patch('web.services.connection')
    def test_get_id_from_number_not_found(self, mock_connection):
        """Test get_id_from_number when account not found."""
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = None
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        # This should raise an exception since it tries to access row[0]
        with self.assertRaises(TypeError):
            CashAccountService.get_id_from_number('nonexistent')


class TestCreditAccountService(BaseUnitTestCase):
    """Unit tests for CreditAccountService."""

    @patch('web.models.CreditAccount.objects.raw')
    def test_find_credit_accounts_by_username(self, mock_raw):
        """Test find_credit_accounts_by_username SQL injection vulnerability."""
        mock_accounts = [Mock(), Mock()]
        mock_raw.return_value = mock_accounts

        result = CreditAccountService.find_credit_accounts_by_username('testuser')

        # Verify the vulnerable SQL query
        expected_sql = "select * from web_creditaccount  where username='testuser'"
        mock_raw.assert_called_once_with(expected_sql)
        self.assertEqual(result, mock_accounts)

    @patch('web.models.CreditAccount.objects.raw')
    def test_find_credit_accounts_sql_injection(self, mock_raw):
        """Test SQL injection vulnerability in find_credit_accounts_by_username."""
        mock_accounts = [Mock()]
        mock_raw.return_value = mock_accounts

        # Test with SQL injection payload
        malicious_username = "'; UPDATE web_creditaccount SET availableBalance=999999; --"

        result = CreditAccountService.find_credit_accounts_by_username(malicious_username)

        # Verify the vulnerability is preserved
        called_sql = mock_raw.call_args[0][0]
        self.assertIn("UPDATE web_creditaccount", called_sql)
        self.assertIn("999999", called_sql)

    @patch('web.services.connection')
    def test_update_credit_account(self, mock_connection):
        """Test update_credit_account SQL injection vulnerability."""
        mock_cursor = Mock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        CreditAccountService.update_credit_account(123, 2500.75)

        # Verify the vulnerable SQL update query
        expected_sql = "UPDATE web_creditaccount SET availableBalance='2500.75' WHERE cashAccountId ='123'"
        mock_cursor.execute.assert_called_once_with(expected_sql)

    @patch('web.services.connection')
    def test_update_credit_account_sql_injection(self, mock_connection):
        """Test SQL injection vulnerability in update_credit_account."""
        mock_cursor = Mock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        # Test with malicious values
        malicious_balance = "'; DROP TABLE web_creditaccount; --"
        malicious_id = "'; DELETE FROM web_creditaccount; --"

        CreditAccountService.update_credit_account(malicious_id, malicious_balance)

        # Verify the vulnerability allows injection
        called_sql = mock_cursor.execute.call_args[0][0]
        self.assertIn("DROP TABLE", called_sql)
        self.assertIn("DELETE FROM", called_sql)


class TestActivityService(BaseUnitTestCase):
    """Unit tests for ActivityService."""

    @patch('web.models.Transaction.objects.raw')
    def test_find_transactions_by_cash_account_number(self, mock_raw):
        """Test find_transactions_by_cash_account_number SQL injection vulnerability."""
        mock_transactions = [Mock(), Mock()]
        mock_raw.return_value = mock_transactions

        result = ActivityService.find_transactions_by_cash_account_number('1234567890')

        # Verify the vulnerable SQL query
        expected_sql = "SELECT * FROM web_transaction WHERE number = '1234567890'"
        mock_raw.assert_called_once_with(expected_sql)
        self.assertEqual(result, mock_transactions)

    @patch('web.models.Transaction.objects.raw')
    def test_find_transactions_sql_injection(self, mock_raw):
        """Test SQL injection vulnerability in find_transactions_by_cash_account_number."""
        mock_transactions = [Mock()]
        mock_raw.return_value = mock_transactions

        # Test with SQL injection payload
        malicious_number = "'; SELECT * FROM web_account; --"

        result = ActivityService.find_transactions_by_cash_account_number(malicious_number)

        # Verify the vulnerability is preserved
        called_sql = mock_raw.call_args[0][0]
        self.assertIn("SELECT * FROM web_account", called_sql)

    @patch('web.services.connection')
    def test_insert_new_activity(self, mock_connection):
        """Test insert_new_activity with parameterized query."""
        mock_cursor = Mock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        from datetime import datetime
        test_date = datetime.now()

        ActivityService.insert_new_activity(
            test_date, 'Test Transaction', '1234567890', 100.50, 1400.25
        )

        # Verify the parameterized SQL insert
        expected_sql = (
            "INSERT INTO web_transaction "
            "(date, description, number, amount, availablebalance) "
            "VALUES (%s, %s, %s, %s, %s)"
        )
        mock_cursor.execute.assert_called_once_with(
            expected_sql, [test_date, 'Test Transaction', '1234567890', 100.50, 1400.25]
        )


class TestTransferService(BaseUnitTestCase):
    """Unit tests for TransferService."""

    def setUp(self):
        """Set up test data."""
        super().setUp()
        from datetime import datetime
        self.transfer_data = {
            'fromAccount': '1234567890',
            'toAccount': '0987654321',
            'description': 'Test Transfer',
            'amount': 100.00,
            'fee': 20.00,
            'username': 'testuser',
            'date': datetime.now()
        }

    @patch('web.services.connection')
    def test_insert_transfer(self, mock_connection):
        """Test insert_transfer with parameterized query."""
        mock_cursor = Mock()
        mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

        transfer = Transfer(**self.transfer_data)

        TransferService.insert_transfer(transfer)

        # Verify the parameterized SQL insert
        expected_sql = (
            "INSERT INTO web_transfer "
            "(fromAccount, toAccount, description, amount, fee, username, date) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)"
        )
        mock_cursor.execute.assert_called_once_with(
            expected_sql,
            [
                transfer.fromAccount, transfer.toAccount, transfer.description,
                transfer.amount, transfer.fee, transfer.username, transfer.date
            ]
        )

    @patch('web.services.TransferService.insert_transfer')
    @patch('web.services.CashAccountService.get_from_account_actual_amount')
    @patch('web.services.CashAccountService.get_id_from_number')
    @patch('web.services.CreditAccountService.update_credit_account')
    @patch('web.services.ActivityService.insert_new_activity')
    def test_createNewTransfer_complete_workflow(self, mock_insert_activity,
                                                mock_update_credit, mock_get_id,
                                                mock_get_amount, mock_insert_transfer):
        """Test createNewTransfer complete workflow with all dependencies."""
        # Setup mocks
        mock_get_amount.side_effect = [1000.00, 500.00]  # from and to account balances
        mock_get_id.side_effect = [1, 2]  # from and to account IDs

        transfer = Transfer(**self.transfer_data)

        # Execute the transfer
        TransferService.createNewTransfer(transfer)

        # Verify all service calls
        mock_insert_transfer.assert_called_once_with(transfer)

        # Verify amount calculations
        mock_get_amount.assert_has_calls([
            call('1234567890'),  # from account
            call('0987654321')   # to account
        ])

        mock_get_id.assert_has_calls([
            call('1234567890'),  # from account
            call('0987654321')   # to account
        ])

        # Verify balance updates
        mock_update_credit.assert_has_calls([
            call(1, 880.0),  # from account: 1000 - 100 - 20 = 880
            call(2, 600.0)   # to account: 500 + 100 = 600
        ])

        # Verify activity records (3 activities should be created)
        self.assertEqual(mock_insert_activity.call_count, 3)

    @patch('web.services.TransferService.insert_transfer')
    @patch('web.services.CashAccountService.get_from_account_actual_amount')
    @patch('web.services.CashAccountService.get_id_from_number')
    @patch('web.services.CreditAccountService.update_credit_account')
    @patch('web.services.ActivityService.insert_new_activity')
    def test_createNewTransfer_description_truncation(self, mock_insert_activity,
                                                     mock_update_credit, mock_get_id,
                                                     mock_get_amount, mock_insert_transfer):
        """Test createNewTransfer truncates long descriptions."""
        # Setup mocks
        mock_get_amount.side_effect = [1000.00, 500.00]
        mock_get_id.side_effect = [1, 2]

        # Create transfer with long description
        long_desc_data = self.transfer_data.copy()
        long_desc_data['description'] = 'This is a very long description that should be truncated'
        transfer = Transfer(**long_desc_data)

        TransferService.createNewTransfer(transfer)

        # Verify description is truncated to 12 characters in activity records
        activity_calls = mock_insert_activity.call_args_list

        # Check the transfer activity descriptions
        transfer_desc_call = activity_calls[0][0][1]  # First activity description
        self.assertIn('This is a ve', transfer_desc_call)  # First 12 chars
        self.assertEqual(len(transfer_desc_call.split(': ')[1]), 12)

    @patch('web.services.TransferService.insert_transfer')
    @patch('web.services.CashAccountService.get_from_account_actual_amount')
    @patch('web.services.CashAccountService.get_id_from_number')
    @patch('web.services.CreditAccountService.update_credit_account')
    @patch('web.services.ActivityService.insert_new_activity')
    def test_createNewTransfer_transaction_atomic(self, mock_insert_activity,
                                                 mock_update_credit, mock_get_id,
                                                 mock_get_amount, mock_insert_transfer):
        """Test createNewTransfer uses transaction.atomic decorator."""
        # Verify the method has the transaction.atomic decorator
        import inspect
        from django.db import transaction

        # Check if the method is decorated (this tests the decorator is present)
        self.assertTrue(hasattr(TransferService.createNewTransfer, '__wrapped__'))

        # Setup mocks for successful execution
        mock_get_amount.side_effect = [1000.00, 500.00]
        mock_get_id.side_effect = [1, 2]

        transfer = Transfer(**self.transfer_data)

        # Should execute without error
        TransferService.createNewTransfer(transfer)

        # All mocks should have been called
        mock_insert_transfer.assert_called_once()
        self.assertEqual(mock_update_credit.call_count, 2)
        self.assertEqual(mock_insert_activity.call_count, 3)


class TestStorageService(BaseUnitTestCase):
    """Unit tests for StorageService."""

    def setUp(self):
        """Set up test data."""
        super().setUp()
        self.storage_service = StorageService()

    @patch('web.services.os.path.exists')
    @patch('web.services.os.path.join')
    def test_exists_file_found(self, mock_join, mock_exists):
        """Test exists returns True when file exists."""
        mock_join.return_value = '/fake/path/avatar.jpg'
        mock_exists.return_value = True

        result = self.storage_service.exists('avatar.jpg')

        self.assertTrue(result)
        mock_exists.assert_called_once_with('/fake/path/avatar.jpg')

    @patch('web.services.os.path.exists')
    @patch('web.services.os.path.join')
    def test_exists_file_not_found(self, mock_join, mock_exists):
        """Test exists returns False when file doesn't exist."""
        mock_join.return_value = '/fake/path/missing.jpg'
        mock_exists.return_value = False

        result = self.storage_service.exists('missing.jpg')

        self.assertFalse(result)
        mock_exists.assert_called_once_with('/fake/path/missing.jpg')

    @patch('builtins.open', new_callable=MagicMock)
    @patch('web.services.os.path.join')
    def test_load_file_success(self, mock_join, mock_open):
        """Test load returns file data when successful."""
        mock_join.return_value = '/fake/path/avatar.jpg'
        mock_file_handle = MagicMock()
        mock_file_handle.read.return_value = b'fake image data'
        mock_open.return_value.__enter__.return_value = mock_file_handle

        result = self.storage_service.load('avatar.jpg')

        self.assertEqual(result, b'fake image data')
        mock_open.assert_called_once_with('/fake/path/avatar.jpg', 'rb')
        mock_file_handle.read.assert_called_once()

    @patch('builtins.open', new_callable=MagicMock)
    @patch('web.services.os.path.join')
    def test_load_file_error(self, mock_join, mock_open):
        """Test load raises exception when file can't be read."""
        mock_join.return_value = '/fake/path/missing.jpg'
        mock_open.side_effect = FileNotFoundError("File not found")

        with self.assertRaises(FileNotFoundError):
            self.storage_service.load('missing.jpg')

    @patch('builtins.open', new_callable=MagicMock)
    @patch('web.services.os.path.join')
    def test_save_file_success(self, mock_join, mock_open):
        """Test save writes data to file successfully."""
        mock_join.return_value = '/fake/path/new_avatar.jpg'
        mock_file_handle = MagicMock()
        mock_open.return_value.__enter__.return_value = mock_file_handle

        test_data = b'new image data'
        self.storage_service.save(test_data, 'new_avatar.jpg')

        mock_open.assert_called_once_with('/fake/path/new_avatar.jpg', 'wb')
        mock_file_handle.write.assert_called_once_with(test_data)

    @patch('builtins.open', new_callable=MagicMock)
    @patch('web.services.os.path.join')
    def test_save_file_error(self, mock_join, mock_open):
        """Test save raises exception when file can't be written."""
        mock_join.return_value = '/fake/path/readonly.jpg'
        mock_open.side_effect = PermissionError("Permission denied")

        with self.assertRaises(PermissionError):
            self.storage_service.save(b'data', 'readonly.jpg')

    def test_storage_service_folder_path(self):
        """Test StorageService folder path construction."""
        # This tests the actual folder path construction logic
        from django.conf import settings
        import os

        expected_path = os.path.join(settings.BASE_DIR, "src", "web", "static", "resources", "avatars")
        self.assertEqual(self.storage_service.folder, expected_path)

    @patch('web.services.os.path.join')
    def test_path_traversal_vulnerability(self, mock_join):
        """Test potential path traversal vulnerability in file operations."""
        # Test with path traversal attempt
        malicious_filename = '../../../etc/passwd'

        # The service doesn't validate the filename, allowing path traversal
        mock_join.side_effect = lambda *args: '/'.join(args)

        # This would construct a dangerous path
        expected_path = f"{self.storage_service.folder}/../../../etc/passwd"

        with patch('web.services.os.path.exists') as mock_exists:
            mock_exists.return_value = True
            result = self.storage_service.exists(malicious_filename)

            # Verify the vulnerability: no path validation
            mock_join.assert_called_with(self.storage_service.folder, malicious_filename)
            self.assertTrue(result)  # The method would return True if file exists


@pytest.mark.unit
class TestServiceErrorHandling(object):
    """Pytest-style tests for service error handling."""

    @pytest.mark.django_db
    def test_account_service_database_connection_error(self, mock_account_service):
        """Test AccountService handles database connection errors."""
        from django.db import DatabaseError

        with patch('web.models.Account.objects.raw') as mock_raw:
            mock_raw.side_effect = DatabaseError("Connection failed")

            with pytest.raises(DatabaseError):
                AccountService.find_all_users()

    @pytest.mark.django_db
    def test_cash_account_service_cursor_error(self):
        """Test CashAccountService handles cursor errors."""
        with patch('web.services.connection') as mock_connection:
            mock_connection.cursor.side_effect = Exception("Database unavailable")

            with pytest.raises(Exception):
                CashAccountService.get_from_account_actual_amount('1234567890')

    def test_storage_service_file_system_errors(self):
        """Test StorageService handles various file system errors."""
        storage = StorageService()

        # Test file not found error
        with patch('builtins.open', side_effect=FileNotFoundError()):
            with pytest.raises(FileNotFoundError):
                storage.load('nonexistent.jpg')

        # Test permission error
        with patch('builtins.open', side_effect=PermissionError()):
            with pytest.raises(PermissionError):
                storage.save(b'data', 'readonly.jpg')

        # Test IO error
        with patch('builtins.open', side_effect=IOError("Disk full")):
            with pytest.raises(IOError):
                storage.save(b'data', 'file.jpg')

    @pytest.mark.django_db
    def test_transfer_service_partial_failure(self):
        """Test TransferService handles partial transaction failures."""
        from web.models import Transfer
        from datetime import datetime

        transfer_data = {
            'fromAccount': '1234567890',
            'toAccount': '0987654321',
            'description': 'Test Transfer',
            'amount': 100.00,
            'fee': 20.00,
            'username': 'testuser',
            'date': datetime.now()
        }
        transfer = Transfer(**transfer_data)

        with patch('web.services.TransferService.insert_transfer') as mock_insert:
            with patch('web.services.CashAccountService.get_from_account_actual_amount') as mock_get_amount:
                # Simulate failure in middle of transaction
                mock_insert.return_value = None
                mock_get_amount.side_effect = Exception("Database connection lost")

                with pytest.raises(Exception):
                    TransferService.createNewTransfer(transfer)



    def test_credit_account_service_type_conversion_errors(self):
        """Test CreditAccountService handles type conversion errors."""
        with patch('web.services.connection') as mock_connection:
            mock_cursor = Mock()
            mock_connection.cursor.return_value.__enter__.return_value = mock_cursor

            # Test with non-numeric values that cause SQL errors
            CreditAccountService.update_credit_account("not_a_number", "not_a_float")

            # The service doesn't validate input types (vulnerability)
            # It constructs SQL with string concatenation
            called_sql = mock_cursor.execute.call_args[0][0]
            assert "not_a_number" in called_sql
            assert "not_a_float" in called_sql


class TestModelValidationEdgeCases(TestCase):
    """Test model validation edge cases."""

    def test_account_empty_fields(self):
        """Test Account model with empty field values."""
        # Test with completely empty fields
        try:
            account = Account.objects.create(
                username='',
                name='',
                surname='',
                password=''
            )
            # If this succeeds, empty fields are allowed (potential vulnerability)
            self.assertEqual(account.username, '')
        except Exception:
            # If this fails, empty fields are properly validated
            pass

    def test_account_max_length_validation(self):
        """Test Account model max_length constraints."""
        # Test with exactly max length (80 characters)
        max_length_string = 'a' * 80

        account = Account.objects.create(
            username=max_length_string,
            name=max_length_string,
            surname=max_length_string,
            password=max_length_string
        )

        self.assertEqual(len(account.username), 80)
        self.assertEqual(len(account.name), 80)

    def test_account_beyond_max_length(self):
        """Test Account model beyond max_length limits."""
        from django.core.exceptions import ValidationError
        # Test with beyond max length (81 characters)
        beyond_max_string = 'a' * 81

        with self.assertRaises(ValidationError):
            account = Account(
                username=beyond_max_string,
                name='Test',
                surname='User',
                password='test'
            )
            account.full_clean()
            account.save()

    def test_cash_account_balance_precision(self):
        """Test CashAccount balance precision handling."""
        # Test with many decimal places
        high_precision_balance = 1234.123456789

        cash_account = CashAccount.objects.create(
            number='1234567890',
            username='testuser',
            description='Precision Test',
            availableBalance=high_precision_balance
        )

        # Check how precision is handled (might be rounded)
        self.assertIsInstance(cash_account.availableBalance, float)

    def test_cash_account_negative_balance(self):
        """Test CashAccount with negative balance."""
        try:
            cash_account = CashAccount.objects.create(
                number='9999999999',
                username='testuser',
                description='Negative Test',
                availableBalance=-500.00
            )
            # If this succeeds, negative balances are allowed (business logic vulnerability)
            self.assertEqual(cash_account.availableBalance, -500.00)
        except Exception:
            # If this fails, negative balances are properly prevented
            pass

    def test_transfer_zero_amount(self):
        """Test Transfer with zero amount."""
        from datetime import datetime

        try:
            transfer = Transfer.objects.create(
                fromAccount='1111111111',
                toAccount='2222222222',
                description='Zero Amount Transfer',
                amount=0.0,
                fee=20.0,
                username='testuser',
                date=datetime.now()
            )
            # If this succeeds, zero amount transfers are allowed (potential business rule violation)
            self.assertEqual(transfer.amount, 0.0)
        except Exception:
            # If this fails, zero amounts are properly validated
            pass

    def test_transfer_negative_fee(self):
        """Test Transfer with negative fee."""
        from datetime import datetime

        try:
            transfer = Transfer.objects.create(
                fromAccount='3333333333',
                toAccount='4444444444',
                description='Negative Fee Transfer',
                amount=100.0,
                fee=-10.0,  # Negative fee (potential vulnerability)
                username='testuser',
                date=datetime.now()
            )
            # If this succeeds, negative fees are allowed (vulnerability)
            self.assertEqual(transfer.fee, -10.0)
        except Exception:
            # If this fails, negative fees are properly validated
            pass

    def test_transfer_same_account(self):
        """Test Transfer to same account."""
        from datetime import datetime

        try:
            transfer = Transfer.objects.create(
                fromAccount='5555555555',
                toAccount='5555555555',  # Same as fromAccount
                description='Self Transfer',
                amount=100.0,
                fee=20.0,
                username='testuser',
                date=datetime.now()
            )
            # If this succeeds, self-transfers are allowed (potential business rule violation)
            self.assertEqual(transfer.fromAccount, transfer.toAccount)
        except Exception:
            # If this fails, self-transfers are properly prevented
            pass

    def test_transaction_future_date(self):
        """Test Transaction with future date."""
        from datetime import datetime, timedelta

        future_date = datetime.now() + timedelta(days=30)

        try:
            transaction = Transaction.objects.create(
                number='FUTURE001',
                description='Future Transaction',
                amount=100.0,
                availableBalance=900.0,
                date=future_date
            )
            # If this succeeds, future dates are allowed (potential business rule violation)
            self.assertGreater(transaction.date, datetime.now())
        except Exception:
            # If this fails, future dates are properly validated
            pass
