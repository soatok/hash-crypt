<?php
declare(strict_types=1);
namespace Soatok\HashCrypt;

/**
 * Class Key
 */
class Key
{
    /** @var string $key */
    protected $key = '';

    /**
     * Key constructor.
     * @param string $keyMaterial
     */
    public function __construct(string $keyMaterial = '')
    {
        $this->key = $keyMaterial;
    }

    /**
     * @return self
     * @throws \Exception
     */
    public static function generate(): self
    {
        return new self(\random_bytes(32));
    }

    /**
     * @return string
     */
    public function getKey(): string
    {
        return $this->key;
    }
}
