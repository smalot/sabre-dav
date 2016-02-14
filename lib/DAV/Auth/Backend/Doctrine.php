<?php

namespace Sabre\DAV\Auth\Backend;

use Doctrine\ORM\EntityManager;
use Doctrine\ORM\Query\ResultSetMapping;

/**
 * This is an authentication backend that uses a database to manage passwords.
 *
 * @author Sebastien Malot (sebastien@malot.fr)
 * @license http://sabre.io/license/ Modified BSD License
 */
class Doctrine extends AbstractDigest
{
    /**
     * Doctrine Entity Manager.
     *
     * @var EntityManager
     */
    protected $entityManager;

    /**
     * Database table name we'll be using
     *
     * @var string
     */
    public $tableName = 'users';

    /**
     * Creates the backend object.
     *
     * If the filename argument is passed in, it will parse out the specified file fist.
     *
     * @param EntityManager $entityManager
     */
    function __construct(EntityManager $entityManager) {
        $this->entityManager = $entityManager;
    }

    /**
     * Returns the digest hash for a user.
     *
     * @param string $realm
     * @param string $username
     * @return string|null
     */
    function getDigestHash($realm, $username) {
        $rsm = new ResultSetMapping();
        $rsm->addScalarResult('digesta1', 'digesta1');

        $sql = 'SELECT digesta1 FROM ' . $this->tableName . ' WHERE username = ?';
        $query = $this->entityManager->createNativeQuery($sql, $rsm);
        $query->setParameter(1, $username);

        $rows = $query->getResult();

        if (count($rows)) {
            return $rows[0]['digesta1'];
        } else {
            return null;
        }
    }
}
